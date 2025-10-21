#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use etherip_xdp_common::{iface, ipv6, mac, vlan};

use aya_ebpf::{
    bindings::xdp_action,
    helpers::gen::{bpf_redirect, bpf_xdp_adjust_head},
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::{error, info};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
};

const ETH_P_VLAN: u16 = 0x8100;
const ETH_P_QINQ: u16 = 0x88A8;
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

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

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct VlanHdr {
    tci: u16,
    ether_type: u16,
}

impl VlanHdr {
    const LEN: usize = core::mem::size_of::<Self>();

    fn vlan_id(&self) -> u16 {
        u16::from_be(self.tci) & 0x0fff
    }

    fn inner_ether_type(&self) -> u16 {
        u16::from_be(self.ether_type)
    }
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

    let mut vlan_id = vlan::VLAN_ID_NATIVE;

    if 0 != bpf_xdp_adjust_head(
        ctx.ctx,
        0 - (EthHdr::LEN as i32 + Ipv6Hdr::LEN as i32 + EtheripHdr::LEN as i32),
    ) {
        error!(&ctx, "Failed to adjust head");
        return Ok(xdp_action::XDP_DROP);
    }

    let new_frame_len = ((*ctx.ctx).data_end - (*ctx.ctx).data) as usize;

    let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)?;

    (*eth_hdr).dst_addr = mac::from_u64(*MAC_ADDR_MAP.get(&mac::MAC_ADDR_GATEWAY).unwrap_or(&0));
    (*eth_hdr).src_addr = mac::from_u64(*MAC_ADDR_MAP.get(&mac::MAC_ADDR_LOCAL).unwrap_or(&0));
    (*eth_hdr).ether_type = EtherType::Ipv6.into();

    let ipv6_hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    (*ipv6_hdr).set_version(6);
    (*ipv6_hdr).set_dscp_ecn(0, 0);
    (*ipv6_hdr).set_flow_label(0);
    (*ipv6_hdr).hop_limit = 64;

    let etherip_hdr = ptr_at::<EtheripHdr>(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
    (*etherip_hdr).etherip_version = 0x30;
    (*etherip_hdr).reserved = 0;

    let mut offset = EthHdr::LEN + Ipv6Hdr::LEN + EtheripHdr::LEN;
    let mut target_mss: usize = 1384;
    let inner_eth_hdr = ptr_at::<EthHdr>(&ctx, offset)?;
    offset += EthHdr::LEN;
    let ether_type_ptr = core::ptr::addr_of!((*inner_eth_hdr).ether_type) as *const u16;
    let mut inner_ethertype = u16::from_be(core::ptr::read_unaligned(ether_type_ptr));

    if inner_ethertype == ETH_P_VLAN || inner_ethertype == ETH_P_QINQ {
        let vlan_hdr_ptr = ptr_at::<VlanHdr>(&ctx, offset)?;
        let vlan_hdr = core::ptr::read_unaligned(vlan_hdr_ptr);
        let candidate_vlan = vlan_hdr.vlan_id();
        if candidate_vlan == vlan::VLAN_ID_LOCAL {
            return Ok(xdp_action::XDP_PASS);
        }
        if candidate_vlan > vlan::VLAN_ID_MAX && candidate_vlan != vlan::VLAN_ID_NATIVE {
            return Ok(xdp_action::XDP_PASS);
        }
        vlan_id = candidate_vlan;
        inner_ethertype = vlan_hdr.inner_ether_type();
        offset += VlanHdr::LEN;

        if inner_ethertype == ETH_P_VLAN || inner_ethertype == ETH_P_QINQ {
            info!(&ctx, "Nested VLAN tags are not supported");
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let remote_addr = match IPV6_ADDR_MAP.get(&vlan_id) {
        Some(addr) if *addr != 0 => *addr,
        _ => return Ok(xdp_action::XDP_PASS),
    };
    let local_addr = match IPV6_ADDR_MAP.get(&vlan::VLAN_ID_LOCAL) {
        Some(addr) if *addr != 0 => *addr,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    let ip_remote_addr = ipv6::from_u128(remote_addr);
    let ip_local_addr = ipv6::from_u128(local_addr);

    (*ipv6_hdr).dst_addr = ip_remote_addr;
    (*ipv6_hdr).src_addr = ip_local_addr;
    (*ipv6_hdr).next_hdr = IpProto::Etherip;
    (*ipv6_hdr).payload_len = u16::to_be_bytes((new_frame_len - EthHdr::LEN - Ipv6Hdr::LEN) as u16);

    loop {
        match inner_ethertype {
            ETH_P_IPV4 => {
                let inner_ip_hdr = ptr_at::<Ipv4Hdr>(&ctx, offset)?;
                if (*inner_ip_hdr).proto != IpProto::Tcp {
                    break;
                }
                offset += Ipv4Hdr::LEN;
                target_mss = 1404;
            }
            ETH_P_IPV6 => {
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
                let mss =
                    u16::from_be(core::ptr::read_unaligned(ptr_at::<u16>(&ctx, offset)?) as u16);
                if mss > target_mss as u16 {
                    info!(&ctx, "MSS: {} -> {}", mss, target_mss);
                    core::ptr::write_unaligned(
                        ptr_at::<u16>(&ctx, offset)?,
                        u16::to_be(target_mss as u16) as u16,
                    );

                    // calculate new checksum
                    let sum16: [u8; 2];

                    let old_mss_inv = !(mss as u32);
                    let new_mss = target_mss as u32;

                    let old_sum = u16::from_be_bytes((*inner_tcp_hdr).check) as u32;
                    let undo = (!old_sum).wrapping_add(old_mss_inv);
                    let mut sum = undo
                        .wrapping_add(if undo < old_mss_inv { 1 } else { 0 })
                        .wrapping_add(new_mss);
                    if sum < new_mss {
                        sum = sum.wrapping_add(1);
                    }

                    // fold 32-bit sum to 16 bits
                    sum = (sum >> 16).wrapping_add(sum & 0xFFFF);
                    sum = (sum >> 16).wrapping_add(sum & 0xFFFF);

                    // calculate the new checksum
                    sum16 = u16::to_be_bytes(!sum as u16);

                    // Update the checksum field in the TCP header
                    let csum = &mut (*inner_tcp_hdr).check;

                    // update checksum
                    core::ptr::write_unaligned(csum, sum16);
                }
            } else {
                info!(&ctx, "Not a TCP MSS option");
            }
        }
        break;
    }

    bpf_redirect(outer_if_index, 0);

    Ok(xdp_action::XDP_REDIRECT)
}

unsafe fn decapsulate(ctx: XdpContext) -> Result<u32, ()> {
    let inner_if_index = *IF_INDEX_MAP.get(&iface::IF_INDEX_INNER).unwrap_or(&0);
    if inner_if_index == 0 {
        info!(&ctx, "Unknown inner interface");
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_hdr = ptr_at::<EthHdr>(&ctx, 0)?;

    let local_addr = mac::from_u64(*MAC_ADDR_MAP.get(&mac::MAC_ADDR_LOCAL).unwrap_or(&0));
    if (*eth_hdr).dst_addr != local_addr {
        let dst_addr = (*eth_hdr).dst_addr;
        info!(
            &ctx,
            "MAC mismatch: {}:{}:{}:{}:{}:{} vs {}:{}:{}:{}:{}:{}",
            local_addr[0],
            local_addr[1],
            local_addr[2],
            local_addr[3],
            local_addr[4],
            local_addr[5],
            dst_addr[0],
            dst_addr[1],
            dst_addr[2],
            dst_addr[3],
            dst_addr[4],
            dst_addr[5]
        );
        return Ok(xdp_action::XDP_PASS);
    }

    if core::ptr::read_unaligned(&raw const (*eth_hdr).ether_type) != EtherType::Ipv6.into() {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv6_hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    let ip_local_addr = ipv6::from_u128(*IPV6_ADDR_MAP.get(&vlan::VLAN_ID_LOCAL).unwrap_or(&0));
    if (*ipv6_hdr).dst_addr != ip_local_addr {
        info!(&ctx, "IP addr mismatch");
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_remote_addr = (*ipv6_hdr).src_addr;
    let vlan_id = *VLAN_ID_MAP
        .get(&ipv6::to_u128(ip_remote_addr))
        .unwrap_or(&vlan::VLAN_ID_LOCAL);

    if vlan_id == vlan::VLAN_ID_LOCAL {
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

    let inner_offset = EthHdr::LEN + Ipv6Hdr::LEN + EtheripHdr::LEN;
    let inner_eth_hdr = ptr_at::<EthHdr>(&ctx, inner_offset)?;
    let inner_ethertype_be = core::ptr::read_unaligned(&raw const (*inner_eth_hdr).ether_type);
    let inner_ethertype = u16::from_be(inner_ethertype_be);
    let has_vlan_tag = inner_ethertype == ETH_P_VLAN || inner_ethertype == ETH_P_QINQ;

    if 0 != bpf_xdp_adjust_head(ctx.ctx, inner_offset as i32) {
        error!(&ctx, "Failed to adjust head");
        return Ok(xdp_action::XDP_DROP);
    }

    if vlan_id != vlan::VLAN_ID_NATIVE {
        if ensure_vlan_tag(&ctx, vlan_id, has_vlan_tag, inner_ethertype_be).is_err() {
            error!(&ctx, "Failed to apply VLAN tag");
            return Ok(xdp_action::XDP_DROP);
        }
    }

    let flag: xdp_action::Type = bpf_redirect(inner_if_index, 0).try_into().map_err(|_| ())?;

    if flag != xdp_action::XDP_REDIRECT {
        error!(&ctx, "Failed to redirect");
        return Ok(xdp_action::XDP_ABORTED);
    }

    //info!(&ctx, "Redirected to {}", inner_if_index);
    Ok(xdp_action::XDP_REDIRECT)
}

#[inline(always)]
unsafe fn ensure_vlan_tag(
    ctx: &XdpContext,
    vlan_id: u16,
    had_vlan_tag: bool,
    original_ethertype_be: u16,
) -> Result<(), ()> {
    if had_vlan_tag {
        let vlan_hdr = ptr_at::<VlanHdr>(ctx, EthHdr::LEN)?;
        let existing_tci_be = core::ptr::read_unaligned(&raw const (*vlan_hdr).tci);
        let mut tci = u16::from_be(existing_tci_be);
        tci = (tci & 0xF000) | (vlan_id & 0x0FFF);
        core::ptr::write_unaligned(core::ptr::addr_of_mut!((*vlan_hdr).tci), u16::to_be(tci));
        return Ok(());
    }

    if bpf_xdp_adjust_head(ctx.ctx, -(VlanHdr::LEN as i32)) != 0 {
        return Err(());
    }

    let new_start = ctx.data() as *mut u8;
    let old_start = unsafe { new_start.add(VlanHdr::LEN) } as *const u8;
    core::ptr::copy(old_start, new_start, EthHdr::LEN);

    let eth_hdr = ptr_at::<EthHdr>(ctx, 0)?;
    (*eth_hdr).ether_type = EtherType::Ieee8021q.into();

    let vlan_hdr = ptr_at::<VlanHdr>(ctx, EthHdr::LEN)?;
    let tci = vlan_id & 0x0FFF;
    core::ptr::write_unaligned(core::ptr::addr_of_mut!((*vlan_hdr).tci), u16::to_be(tci));
    core::ptr::write_unaligned(
        core::ptr::addr_of_mut!((*vlan_hdr).ether_type),
        original_ethertype_be,
    );

    Ok(())
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
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
