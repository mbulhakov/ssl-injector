#![no_std]
#![no_main]

use core::cmp::min;

use aya_bpf::{
    macros::{map, uprobe},
    maps::{PerCpuArray, PerfEventArray},
    programs::ProbeContext,
};
use aya_bpf_bindings::helpers::bpf_probe_read;
use aya_log_ebpf::{debug, warn};
use ssl_injector_common::{SslEntry, MAX_BUFFER_SIZE};

#[map]
static mut SSL_WRITE_ARRAY: PerCpuArray<SslEntry> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut SSL_WRITE_EVENTS: PerfEventArray<SslEntry> = PerfEventArray::new(0);

#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    match unsafe { try_ssl_write(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_ssl_write(ctx: ProbeContext) -> Result<u32, u32> {
    debug!(&ctx, "function SSL_write called by libssl");

    let buf: *const core::ffi::c_void = ctx.arg(1).ok_or(1u32)?;
    let num: isize = ctx.arg(2).ok_or(1u32)?;
    if num <= 0 {
        return Ok(0);
    }

    let size = num as usize;
    if size > MAX_BUFFER_SIZE {
        warn!(
            &ctx,
            "Size '{}' is greater then max allowed buffer size '{}', data will be truncated",
            num,
            MAX_BUFFER_SIZE
        );
    }

    let entry: *mut SslEntry = SSL_WRITE_ARRAY.get_ptr_mut(0).ok_or(1u32)?;
    (*entry).size = size;

    let count = min((*entry).size, MAX_BUFFER_SIZE);

    bpf_probe_read(
        (*entry).buffer.as_mut_ptr() as *mut core::ffi::c_void,
        count.try_into().unwrap(),
        buf,
    );
    SSL_WRITE_EVENTS.output(&ctx, &*entry, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
