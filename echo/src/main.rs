use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};
use std::mem::size_of;
use std::path::PathBuf;
use std::sync::Arc;

use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use echo_common::{OpenEvent, PATH_MAX_LEN, COMM_MAX_LEN};
use file_utils::is_harmful_file;
use nix::libc::_SC_PAGE_SIZE;
use server::ProcessInfoCache;
use structopt::StructOpt;

use aya::programs::TracePoint;
use aya::{Bpf, include_bytes_aligned};
use tokio::net::UnixListener;
use tokio::signal;
use tokio::sync::mpsc::Receiver;

mod file_utils;
mod kernel_version;
mod server;
mod unix;
mod metrics;

use crate::file_utils::cstringify;
use crate::kernel_version::{get_kernel_version, extract_kernel_version};
use crate::server::{OpenFilesKernelTracer, ProcessInfo, run_server};
use crate::metrics::Metrics;

const CHANNEL_SIZE: usize = 50;
const CLEAN_UP_TIMER_SEC: u64 = 100;
const PERF_BUFFER_PAGE_COUNT: usize = 4096;
const BUFFER_COUNT: usize = (_SC_PAGE_SIZE as usize * PERF_BUFFER_PAGE_COUNT) / size_of::<OpenEvent>();

#[tokio::main]
async fn main() {
    if let Err(e) = try_main().await {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short, long)]
    socket_path: String,
}

fn openevent_from(buf: &BytesMut) -> OpenEvent {
    let ptr = buf.as_ptr() as *const echo_common::OpenEvent;
    let data = unsafe { ptr.read_unaligned() };
    return data;
}

fn load_bpf() ->  Result<Bpf, anyhow::Error>  {

    let mut bpf = Bpf::load(include_bytes_aligned!(env!("OPEN_TRACER_EBPF_BIN_ABS_PATH")))?;

    let opentrace: &mut TracePoint = bpf.program_mut("echo_trace_open").unwrap().try_into()?;
    opentrace.load()?;
    opentrace.attach("syscalls", "sys_enter_open")?;

    let openat_trace: &mut TracePoint = bpf.program_mut("echo_trace_openat_x").unwrap().try_into()?;
    openat_trace.load()?;
    openat_trace.attach("syscalls", "sys_enter_openat")?;
    openat_trace.attach("syscalls", "sys_enter_openat2")?;
    return Ok(bpf);
}

fn check_kernel_version() -> Result<(), anyhow::Error> {

    let kernel_version = get_kernel_version()?;
    println!("Running under: {}.{}", kernel_version.0, kernel_version.1);

    match extract_kernel_version(env!("OPEN_TRACER_EBPF_BIN_ABS_PATH")) {
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

fn start_events_listeners(bpf: &Bpf, metrics: Arc<Metrics>) -> Result<Receiver<OpenEvent>, anyhow::Error> {
    let mut events_map = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    let (tx, rx) = tokio::sync::mpsc::channel(CHANNEL_SIZE);

    for cpu in online_cpus()? {
        println!("Start cpu #{}", cpu);
        let mut buf_per_cpu = events_map.open(cpu, Some(PERF_BUFFER_PAGE_COUNT))?;
        let tx_per_cpu = tx.clone();
        let metrics_inner = metrics.clone();
        tokio::task::spawn(async move {
            let mut buffers = [BytesMut::with_capacity(size_of::<OpenEvent>()*BUFFER_COUNT)];
            loop {
                let events = match buf_per_cpu.read_events(&mut buffers).await {
                    Err(e) => {
                        println!("cpu {} stopped: {}", cpu, e);
                        return;
                    },
                    Ok(events) => events
                };

                metrics_inner.add_missing(events.lost);
                metrics_inner.add_handled(events.read);

                for i in 0..events.read {
                    let event = openevent_from(&buffers[i]);

                    if let Err(e) = tx_per_cpu.send(event).await {
                        println!("receiver dropped {}", e);
                        return;
                    }
                }

                metrics_inner.update_buffer_capacity(tx_per_cpu.capacity());
            }
        });
    }
    Ok(rx)
}

fn start_info_writer(mut rx: Receiver<OpenEvent>, process_info: Arc<ProcessInfoCache>) {
    let process_info_mut = process_info.clone();
    tokio::task::spawn(async move {
        while let Some(data) = rx.recv().await {
            let pidstr = format!("{}", &data.pid);
            let comm = cstringify(&data.comm, COMM_MAX_LEN);
            let pathname = cstringify(&data.path, PATH_MAX_LEN);

            if !is_harmful_file(pathname.as_str()).unwrap_or(false) {
                continue;
            }
            let mut process_info = unsafe { process_info.info.write().unwrap_unchecked() };
            if !process_info.contains_key(&pidstr) {
                process_info.insert(pidstr.to_owned(), ProcessInfo {
                    command: comm,
                    open_files: HashSet::new(),
                });
            }
            let info = process_info.get_mut(&pidstr);
            unsafe {
                info.unwrap_unchecked().open_files.insert(pathname);
            }
        }
    });

    tokio::task::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(CLEAN_UP_TIMER_SEC)).await;
            process_info_mut.clean_up();
        }
    });
}

fn start_grpc_server(opt: &Opt, mg: OpenFilesKernelTracer) -> Result<(), anyhow::Error> {
    let path = PathBuf::from(opt.socket_path.to_owned());
    let socket = UnixListener::bind(path)?;
    let mg2 = mg.clone();
    tokio::task::spawn(async move {
        let res = run_server(socket, mg2);
        match res.await {
            Ok(_) => (),
            Err(e) => println!("{}", e),
        }
    });
    Ok(())
}

async fn try_main() -> Result<(), anyhow::Error> {

    let opt = Opt::from_args();

    check_kernel_version()?;

    let bpf = load_bpf()?;

    let server = OpenFilesKernelTracer {
        process_info: Arc::new(ProcessInfoCache::new()),
        metrics: Arc::new(Metrics::new()),
    };

    let rx = start_events_listeners(&bpf, server.metrics.clone())?;

    start_info_writer(rx, server.process_info.clone());

    start_grpc_server(&opt, server)?;

    // wait for SIGINT or SIGTERM
    wait_until_terminated(&opt).await
}

fn cleanup(opt: &Opt) {
    if let Err(e) = std::fs::remove_file(opt.socket_path.to_owned()) {
        println!("Socket clean up failed: {}", e);
    }
}

async fn wait_until_terminated(opt: &Opt) -> Result<(), anyhow::Error> {
    signal::ctrl_c().await?;
    println!("Exiting...");
    cleanup(opt);
    Ok(())
}
