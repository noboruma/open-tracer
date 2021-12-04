#![no_std]
#![no_main]

use aya_bpf::{cty::{c_long, c_void}, helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_str, bpf_task_pt_regs, bpf_task_storage_get, bpf_timer_init, bpf_snprintf, bpf_sys_bpf, bpf_sys_close}, macros::{map, tracepoint}, maps::{PerCpuArray, PerfEventArray}, programs::TracePointContext};
use echo_common::OpenEvent;

#[map]
static mut EVENTS: PerfEventArray<OpenEvent> = PerfEventArray::with_max_entries(0, 0);

#[map]
static mut BUFFER: PerCpuArray<OpenEvent> = PerCpuArray::with_max_entries(1, 0);

pub static VERSION: &'static str = env!("MAX_KERNEL_VERSION");

enum SyscallType {
    Open,
    OpenAtX, // Identify both open_at & open_at2
}

#[tracepoint]
pub fn echo_trace_openat_x(ctx: TracePointContext) -> c_long {
    match try_echo_trace(ctx, SyscallType::OpenAtX) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn echo_trace_open(ctx: TracePointContext) -> c_long {
    match try_echo_trace(ctx, SyscallType::Open) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

const MAP_ACCESS_ERROR: i32= -1;

unsafe fn fill_event(ctx: &TracePointContext, event: &mut OpenEvent, syscall_type: SyscallType) -> Result<(), c_long> {
    // Load the pointer to the filename. The offset value can be found running:
    // sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
    let filename_offset: usize = match syscall_type {
        SyscallType::Open => 16,
        SyscallType::OpenAtX => 24,
    };
    let filename_addr: u64 = ctx.read_at(filename_offset)?;
    bpf_sys_close(0);

    // read the filename
    bpf_probe_read_str(filename_addr as *const u8, &mut event.path)?;

    let comm = bpf_get_current_comm()?;
    event.comm = *(&comm as *const [i8; 16] as *mut [u8; 16]);

    event.pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    return Ok(());
}

fn try_echo_trace(ctx: TracePointContext, syscall_type: SyscallType) -> Result<c_long, c_long> {
    unsafe {
        let mut event = BUFFER.get_mut(0).ok_or(MAP_ACCESS_ERROR)?;
        fill_event(&ctx, &mut event, syscall_type)?;
        EVENTS.output(&ctx, &event, 0)
    }
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
