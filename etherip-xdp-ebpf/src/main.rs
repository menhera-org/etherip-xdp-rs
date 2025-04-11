#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use etherip_xdp_common::{
    vlan,
    iface,
    mac,
    ipv6,
};

use aya_ebpf::{
    bindings::xdp_action,
    macros::{
        xdp,
        map,
    },
    programs::XdpContext,
    maps::HashMap,
};
use aya_log_ebpf::{
    info,
    error,
};

use network_types::{
    eth::{
        EthHdr,
        EtherType,
    },
    ip::{
        IpProto,
        Ipv6Hdr,
        Ipv4Hdr,
    },
    tcp::TcpHdr,
};

#[map]
static IF_INDEX_MAP: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(2, 0);

/// VLAN ID to (remote) IPv6 address map
#[map]
static IPV6_ADDR_MAP: HashMap<u16, u128> = HashMap::<u16, u128>::with_max_entries(256, 0);

/// Remote IPv6 address to VLAN ID map
#[map]
static VLAN_ID_MAP: HashMap<u128, u16> = HashMap::<u128, u16>::with_max_entries(256, 0);

/// MAC address database
#[map]
static MAC_ADDR_MAP: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(2, 0);

#[repr(C)]
struct EtheripHdr {
    etherip_version: u8,
    reserved: u8,
}

impl EtheripHdr {
    const LEN: usize = core::mem::size_of::<Self>();
}

#[repr(C)]
struct TcpOpt {
    kind: u8,
    len: u8,
}

impl TcpOpt {
    const LEN: usize = core::mem::size_of::<Self>();
}

#[xdp]
pub fn etherip_xdp_encap(ctx: XdpContext) -> u32 {
    match unsafe { encapsulate(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_DROP,
    }
}

#[xdp]
pub fn etherip_xdp_decap(ctx: XdpContext) -> u32 {
    match unsafe { decapsulate(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_DROP,
    }
}

unsafe fn encapsulate(ctx: XdpContext) -> Result<u32, ()> {
    let outer_if_index = *IF_INDEX_MAP.get(&iface::IF_INDEX_OUTER).unwrap_or(&0);
    if outer_if_index == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let orig_frame_len = ((*ctx.ctx).data_end - (*ctx.ctx).data) as usize;
    if orig_frame_len < EthHdr::LEN {
        return Ok(xdp_action::XDP_DROP);
    }

    // TODO: Implement non-zero VLAN ID handling
    let vlan_id = 0u16;

    (*ctx.ctx).data -= (EthHdr::LEN + Ipv6Hdr::LEN + EtheripHdr::LEN) as u32;

    let new_frame_len = ((*ctx.ctx).data_end - (*ctx.ctx).data) as usize;

    let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)?;

    (*eth_hdr).dst_addr = mac::from_u64(*MAC_ADDR_MAP.get(&mac::MAC_ADDR_GATEWAY).unwrap_or(&0));
    (*eth_hdr).src_addr = mac::from_u64(*MAC_ADDR_MAP.get(&mac::MAC_ADDR_LOCAL).unwrap_or(&0));
    (*eth_hdr).ether_type = EtherType::Ipv6;

    let ipv6_hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    (*ipv6_hdr).set_version(6);
    (*ipv6_hdr).set_priority(0);
    (*ipv6_hdr).flow_label = [0; 3];
    (*ipv6_hdr).hop_limit = 64;

    let ip_local_addr = ipv6::from_u128(*IPV6_ADDR_MAP.get(&vlan::VLAN_ID_LOCAL).unwrap_or(&0));
    let ip_remote_addr = ipv6::from_u128(*IPV6_ADDR_MAP.get(&vlan_id).unwrap_or(&0));

    (*ipv6_hdr).dst_addr.in6_u.u6_addr8 = ip_remote_addr;
    (*ipv6_hdr).src_addr.in6_u.u6_addr8 = ip_local_addr;
    (*ipv6_hdr).next_hdr = IpProto::Etherip;
    (*ipv6_hdr).payload_len = u16::to_be((new_frame_len - EthHdr::LEN - Ipv6Hdr::LEN) as u16);

    let etherip_hdr = ptr_at::<EtheripHdr>(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
    (*etherip_hdr).etherip_version = 0x30;
    (*etherip_hdr).reserved = 0;

    let mut offset = EthHdr::LEN + Ipv6Hdr::LEN + EtheripHdr::LEN;
    let mut target_mss: usize = 1384;
    let inner_eth_hdr = ptr_at::<EthHdr>(&ctx, offset)?;
    offset += EthHdr::LEN;
    loop {
        match (*inner_eth_hdr).ether_type {
            EtherType::Ipv4 => {
                let inner_ip_hdr = ptr_at::<Ipv4Hdr>(&ctx, offset)?;
                if (*inner_ip_hdr).proto != IpProto::Tcp {
                    break;
                }
                offset += Ipv4Hdr::LEN;
                target_mss = 1404;
            }
            EtherType::Ipv6 => {
                let inner_ip_hdr = ptr_at::<Ipv6Hdr>(&ctx, offset)?;
                if (*inner_ip_hdr).next_hdr != IpProto::Tcp {
                    break;
                }
                offset += Ipv6Hdr::LEN;
            }
            _ => {
                break;
            }
        }

        let inner_tcp_hdr = ptr_at::<TcpHdr>(&ctx, offset)?;
        if (*inner_tcp_hdr).syn() != 0 {
            offset += TcpHdr::LEN;
            let tcp_opt = ptr_at::<TcpOpt>(&ctx, offset)?;

            // if MSS option
            if (*tcp_opt).kind == 0x02 && (*tcp_opt).len == 4 {
                // read MSS value
                offset += TcpOpt::LEN;
                let mss = u16::from_be(core::ptr::read_unaligned(ptr_at::<u16>(&ctx, offset)?) as u16);
                if mss > target_mss as u16 {
                    info!(&ctx, "MSS: {} -> {}", mss, target_mss);
                    core::ptr::write_unaligned(ptr_at::<u16>(&ctx, offset)?, u16::to_be(target_mss as u16) as u16);

                    let old_val = mss;
                    let new_val = target_mss;
                    let csum = &raw mut (*inner_tcp_hdr).check as *mut u16;
                    let undo: u32 = !(core::ptr::read_unaligned(csum) as u32 + !(old_val as u32));
                    let new_csum = undo + (if undo < !(old_val as u32) { 1 } else { 0 }) + (new_val as u32);
                    let new_csum = new_csum + (if new_csum < (new_val as u32) { 1 } else { 0 });
                    let new_csum = (new_csum & 0xffff) + ((new_csum >> 16) & 0xffff);
                    let new_csum = (new_csum & 0xffff) + ((new_csum >> 16) & 0xffff);

                    core::ptr::write_unaligned(csum, (!new_csum) as u16);
                }
            } else {
                info!(&ctx, "Not a TCP MSS option");
            }
        }
        break;
    }

    (*ctx.ctx).egress_ifindex = outer_if_index as u32;
    
    Ok(xdp_action::XDP_REDIRECT)
}

unsafe fn decapsulate(ctx: XdpContext) -> Result<u32, ()> {
    let inner_if_index = *IF_INDEX_MAP.get(&iface::IF_INDEX_INNER).unwrap_or(&0);
    if inner_if_index == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)?;

    let local_addr = mac::from_u64(*MAC_ADDR_MAP.get(&mac::MAC_ADDR_LOCAL).unwrap_or(&0));
    if (*eth_hdr).dst_addr != local_addr {
        return Ok(xdp_action::XDP_PASS);
    }

    if core::ptr::read_unaligned(&raw const (*eth_hdr).ether_type) != EtherType::Ipv6 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv6_hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    let ip_local_addr = ipv6::from_u128(*IPV6_ADDR_MAP.get(&vlan::VLAN_ID_LOCAL).unwrap_or(&0));
    if (*ipv6_hdr).dst_addr.in6_u.u6_addr8 != ip_local_addr {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_remote_addr = (*ipv6_hdr).src_addr.in6_u.u6_addr8;
    let vlan_id = *VLAN_ID_MAP.get(&ipv6::to_u128(ip_remote_addr)).unwrap_or(&4095);

    // TODO: Implement non-zero VLAN ID handling
    if vlan_id != 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    if (*ipv6_hdr).next_hdr != IpProto::Etherip {
        return Ok(xdp_action::XDP_PASS);
    }

    let etherip_hdr = ptr_at::<EtheripHdr>(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
    if (*etherip_hdr).etherip_version != 0x30 {
        error!(&ctx, "Invalid EtherIP version");
        return Ok(xdp_action::XDP_PASS);
    }
    if (*etherip_hdr).reserved != 0 {
        error!(&ctx, "Invalid EtherIP reserved field");
        return Ok(xdp_action::XDP_PASS);
    }

    (*ctx.ctx).data += (EthHdr::LEN + Ipv6Hdr::LEN + EtheripHdr::LEN) as u32;
    (*ctx.ctx).egress_ifindex = inner_if_index as u32;

    Ok(xdp_action::XDP_REDIRECT)
}

#[inline(always)]
unsafe fn ptr_at<T>(
    ctx: &XdpContext, offset: usize
) -> Result<*mut T, ()> {
    let start = ctx.data();
    if (start as *const u8).is_null() {
        return Err(());
    }
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *mut T;
    Ok(ptr)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
