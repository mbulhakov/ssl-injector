#![no_std]
#![no_main]

use aya_bpf::{macros::uprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[uprobe]
pub fn ssl_injector(ctx: ProbeContext) -> u32 {
    match try_ssl_injector(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ssl_injector(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function SSL_write called by libssl");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
