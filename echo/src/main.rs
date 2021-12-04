use core::fmt;
use std::convert::{TryFrom, TryInto};
use std::fmt::Display;
use std::mem::size_of;

use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use echo_common::OpenEvent;
use regex::Regex;
use structopt::StructOpt;

use aya::programs::TracePoint;
use aya::Bpf;
use tokio::signal;

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

#[derive(Debug)]
struct KernelError {
    desc: &'static str,
}

impl std::error::Error for KernelError {}
impl Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Kernel error: {}", &self.desc)
    }
}

fn extract_num(s: &str) -> Result<i32, KernelError> {
    let num: Option<i32> = s.parse().ok();
    return match num {
        Some(n) => Ok(n),
        None => Err(KernelError{desc: "Major/Minor not numeric"}),
    };
}

fn extract_kernel_version(input: &str) -> Result<(i32, i32), KernelError> {
    let re = Regex::new(r"([0-9]+)\.([0-9]+)").unwrap();
    let caps = match re.captures(input) {
        Some(s) => s,
        None => return Err(KernelError{desc: "No version"}),
    };

    let major = match &caps.get(1) {
        Some(s) => extract_num(s.as_str())?,
        None => return Err(KernelError{desc: "Major retireval failed"}),
    };
    let minor = match &caps.get(2) {
        Some(s) => extract_num(s.as_str())?,
        None => return Err(KernelError{desc: "Minor retireval failed"}),
    };
    return Ok((major, minor))
}

fn get_kernel_version() -> Result<(i32, i32), KernelError> {
    let res = nix::sys::utsname::uname();
    return extract_kernel_version(res.release());
}

async fn try_main() -> Result<(), anyhow::Error> {
    let kernel_version = get_kernel_version()?;
    println!("Running under: {}.{}", kernel_version.0, kernel_version.1);

    let opt = Opt::from_args();

    match extract_kernel_version(&opt.path) {
        Ok(bpf_kernel_version) =>
        if bpf_kernel_version.0 > kernel_version.0 {
            println!("[Warning] Running kernel is too old");
        } else if bpf_kernel_version.0 == kernel_version.0 && kernel_version.1 < bpf_kernel_version.1 {
            println!("[Warning] Running kernel is too old");
        },
        Err(_) => println!("[Warning] No versioning associated with bpf program"),
    }

    // load the eBPF code
    let mut bpf = Bpf::load_file(&opt.path)?;

    // load the tracepoint
    let opentrace: &mut TracePoint = bpf.program_mut("echo_trace_open")?.try_into()?;
    opentrace.load()?;
    // attach the tracepoint to sys_enter_open
    opentrace.attach("syscalls", "sys_enter_open")?;

    let openat_trace: &mut TracePoint = bpf.program_mut("echo_trace_openat_x")?.try_into()?;
    openat_trace.load()?;
    openat_trace.attach("syscalls", "sys_enter_openat")?;
    openat_trace.attach("syscalls", "sys_enter_openat2")?;

    // Output headers
    println!("PROGRAM, PID, PATH");

    const CPU_BUFFER_CAP: usize = size_of::<OpenEvent>() * 10;
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(CPU_BUFFER_CAP))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {

                    // read the event
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const echo_common::OpenEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    let pathname =
                        String::from_utf8(data.path.to_vec()).unwrap_or("Unknown".to_owned());

                    let comm =
                        String::from_utf8(data.comm.to_vec()).unwrap_or("Unknown".to_owned());

                    println!("{0: <16}, {1: <5}, {2: <32}", comm, data.pid, pathname);
                }
            }
        });
    }

    // wait for SIGINT or SIGTERM
    wait_until_terminated().await
}

async fn wait_until_terminated() -> Result<(), anyhow::Error> {
    signal::ctrl_c().await?;
    println!("Exiting...");
    Ok(())
}
