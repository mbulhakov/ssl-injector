#![no_std]
#![no_main]

use core::cmp::min;

use aya_bpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::ProbeContext,
};
use aya_bpf_bindings::helpers::bpf_probe_read;
use aya_log_ebpf::{debug, warn};
use ssl_injector_common::{SslEntry, MAX_BUFFER_SIZE};

#[map]
static mut SSL_WRITE_ARGS_MAP: HashMap<u64, *const core::ffi::c_void> =
    HashMap::<u64, *const core::ffi::c_void>::with_max_entries(1024, 0);
#[map]
static mut SSL_WRITE_ARRAY: PerCpuArray<SslEntry> = PerCpuArray::with_max_entries(1, 0);
#[map]
static mut SSL_WRITE_EVENTS: PerfEventArray<SslEntry> = PerfEventArray::new(0);

#[map]
static mut SSL_READ_ARGS_MAP: HashMap<u64, *const core::ffi::c_void> =
    HashMap::<u64, *const core::ffi::c_void>::with_max_entries(1024, 0);
#[map]
static mut SSL_READ_ARRAY: PerCpuArray<SslEntry> = PerCpuArray::with_max_entries(1, 0);
#[map]
static mut SSL_READ_EVENTS: PerfEventArray<SslEntry> = PerfEventArray::new(0);

#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    match unsafe { try_ssl_write(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_ssl_write(ctx: ProbeContext) -> Result<u32, u32> {
    debug!(&ctx, "function SSL_write called by libssl");

    let current_pid_tgid = bpf_get_current_pid_tgid();

    let buf: *const core::ffi::c_void = ctx.arg(1).ok_or(1u32)?;

    SSL_WRITE_ARGS_MAP
        .insert(&current_pid_tgid, &buf, 0)
        .map_err(|x| x as u32)?;
    Ok(0)
}

#[uretprobe]
fn ssl_write_ret(ctx: ProbeContext) -> u32 {
    match unsafe { try_ssl_write_ret(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_ssl_write_ret(ctx: ProbeContext) -> Result<u32, u32> {
    let current_pid_tgid = bpf_get_current_pid_tgid();

    let ret_value_len: i32 = ctx.ret().unwrap();
    if ret_value_len <= 0 {
        return Ok(0);
    }

    let size = ret_value_len as usize;
    if size > MAX_BUFFER_SIZE {
        warn!(
            &ctx,
            "Size '{}' is greater then max allowed buffer size '{}', data will be truncated",
            size,
            MAX_BUFFER_SIZE
        );
    }

    if let Some(&buf) = SSL_WRITE_ARGS_MAP.get(&current_pid_tgid) {
        let entry: *mut SslEntry = SSL_WRITE_ARRAY.get_ptr_mut(0).ok_or(1u32)?;
        let count = min(size, MAX_BUFFER_SIZE);

        (*entry).size = count;

        bpf_probe_read(
            (*entry).buffer.as_mut_ptr() as *mut core::ffi::c_void,
            count.try_into().unwrap(),
            buf,
        );
        SSL_WRITE_EVENTS.output(&ctx, &*entry, 0);
    }

    Ok(0)
}

#[uprobe]
pub fn ssl_read(ctx: ProbeContext) -> u32 {
    match unsafe { try_read_write(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_read_write(ctx: ProbeContext) -> Result<u32, u32> {
    debug!(&ctx, "function SSL_read called by libssl");

    let current_pid_tgid = bpf_get_current_pid_tgid();

    let buf: *const core::ffi::c_void = ctx.arg(1).ok_or(1u32)?;

    SSL_READ_ARGS_MAP
        .insert(&current_pid_tgid, &buf, 0)
        .map_err(|x| x as u32)?;
    Ok(0)
}

#[uretprobe]
fn ssl_read_ret(ctx: ProbeContext) -> u32 {
    match unsafe { try_ssl_read_ret(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_ssl_read_ret(ctx: ProbeContext) -> Result<u32, u32> {
    let current_pid_tgid = bpf_get_current_pid_tgid();

    let ret_value_len: i32 = ctx.ret().unwrap();
    if ret_value_len <= 0 {
        return Ok(0);
    }

    let size = ret_value_len as usize;
    if size > MAX_BUFFER_SIZE {
        warn!(
            &ctx,
            "Size '{}' is greater then max allowed buffer size '{}', data will be truncated",
            size,
            MAX_BUFFER_SIZE
        );
    }

    if let Some(&buf) = SSL_READ_ARGS_MAP.get(&current_pid_tgid) {
        let entry: *mut SslEntry = SSL_READ_ARRAY.get_ptr_mut(0).ok_or(1u32)?;
        let count = min(size, MAX_BUFFER_SIZE);

        (*entry).size = count;

        bpf_probe_read(
            (*entry).buffer.as_mut_ptr() as *mut core::ffi::c_void,
            count.try_into().unwrap(),
            buf,
        );
        SSL_READ_EVENTS.output(&ctx, &*entry, 0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
