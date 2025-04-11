#![no_std]
#![no_main]

use core::net::Ipv6Addr;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

const IP_UNSPECIFIED: Ipv6Addr = Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

#[map]
static IP_SRC_ADDR: [u8; 16] = [0; 16];

#[map]
static IP_DST_ADDR: [u8; 16] = [0; 16];

#[xdp]
pub fn etherip_xdp(ctx: XdpContext) -> u32 {
    match try_etherip_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_etherip_xdp(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
