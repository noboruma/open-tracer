use file_utils::is_exe_file;
use kernel_version::get_kernel_version;

use std::convert::{TryFrom, TryInto};
use std::mem::size_of;

use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use echo_common::OpenEvent;
use structopt::StructOpt;

use aya::programs::TracePoint;
use aya::Bpf;
use tokio::signal;

mod file_utils;
mod kernel_version;

use crate::file_utils::cstringify;
use crate::kernel_version::extract_kernel_version;

const CHANNEL_SIZE: usize = 100;

#[tokio::main]
async fn main() {
    if let Err(e) = try_main().await {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    path: String,
}

fn openevent_from(buf: &BytesMut) -> OpenEvent {
    let ptr = buf.as_ptr() as *const echo_common::OpenEvent;
    let data = unsafe { ptr.read_unaligned() };
    return data;
}

fn load_bpf(opt: &Opt) ->  Result<Bpf, anyhow::Error>  {

    let mut bpf = Bpf::load_file(&opt.path)?;

    let opentrace: &mut TracePoint = bpf.program_mut("echo_trace_open").unwrap().try_into()?;
    opentrace.load()?;
    opentrace.attach("syscalls", "sys_enter_open")?;

    let openat_trace: &mut TracePoint = bpf.program_mut("echo_trace_openat_x").unwrap().try_into()?;
    openat_trace.load()?;
    openat_trace.attach("syscalls", "sys_enter_openat")?;
    openat_trace.attach("syscalls", "sys_enter_openat2")?;
    return Ok(bpf);
}

fn check_kernel_version(opt: &Opt) -> Result<(), anyhow::Error> {

    let kernel_version = get_kernel_version()?;
    println!("Running under: {}.{}", kernel_version.0, kernel_version.1);

    match extract_kernel_version(&opt.path) {
        Ok(bpf_kernel_version) =>
            if bpf_kernel_version.0 > kernel_version.0 {
                println!("[Warning] Running kernel is too old");
            } else if bpf_kernel_version.0 == kernel_version.0 && kernel_version.1 < bpf_kernel_version.1 {
                println!("[Warning] Running kernel is too old");
            },
        Err(_) => println!("[Warning] No versioning associated with bpf program"),
    }
    Ok(())
}

async fn try_main() -> Result<(), anyhow::Error> {

    let opt = Opt::from_args();

    check_kernel_version(&opt)?;

    let bpf = load_bpf(&opt)?;

    let mut events_map = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    let (tx, mut rx) = tokio::sync::mpsc::channel(CHANNEL_SIZE);

    for cpu in online_cpus()? {
        println!("Start cpu #{}", cpu);
        let mut buf_per_cpu = events_map.open(cpu, None)?;
        let tx_per_cpu = tx.clone();
        tokio::task::spawn(async move {
            let mut buffers = [BytesMut::with_capacity(size_of::<OpenEvent>())];
            loop {
                let _events = buf_per_cpu.read_events(&mut buffers).await.unwrap();
                let event = openevent_from(&buffers[0]);

                if let Err(e) = tx_per_cpu.send(event).await {
                    println!("receiver dropped {}", e);
                    return;
                }
            }
        });
    }

    tokio::task::spawn(async move {
        println!("PROGRAM PID PATH");
        let mut memo = std::collections::HashSet::<String>::new();
        while let Some(data) = rx.recv().await {
            let pathname = cstringify(&data.path);
            let comm = cstringify(&data.comm);
            let key = pathname.clone() + &comm;
            if !memo.insert(key) {
                continue
            }
            match is_exe_file(pathname.as_str()) {
                Ok(is_exe) => if is_exe {println!("{},{},{}", comm, data.pid, pathname)},
                //Ok(is_exe) => if is_exe {println!("{0: <16}, {1: <5}, {2: <32}", comm, data.pid, pathname)},
                //Err(e) => println!("ERROR accessing {}: {}", pathname, e),
                Err(_) => (),
            };
        }
    });

    // wait for SIGINT or SIGTERM
    wait_until_terminated().await
}

async fn wait_until_terminated() -> Result<(), anyhow::Error> {
    signal::ctrl_c().await?;
    println!("Exiting...");
    Ok(())
}
