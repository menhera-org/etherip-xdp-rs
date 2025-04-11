
pub(crate) mod rtnl;
pub(crate) mod interface;

use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

use etherip_xdp_common::{
    iface,
    vlan,
    mac,
    ipv6,
};

use core::net::Ipv6Addr;
use std::net::SocketAddr;

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
/// A simple XDP program that encapsulates and decapsulates packets using EtherIP.
struct Opt {
    /// The outer interface to transmit encapsulated packets.
    #[clap(short = 'o', long, default_value = "eth0")]
    bind_iface: String,

    /// The inner interface to be bridged by the EtherIP tunnel.
    #[clap(short = 'i', long, default_value = "eth1")]
    bridged_iface: String,

    /// The IPv6 address of the remote end of the tunnel.
    #[clap(short = 'r', long, default_value = "::1")]
    remote_address: String,
}

#[derive(Debug, Clone)]
enum RemoteAddr {
    Static(u128),
    Dynamic(String),
}

impl RemoteAddr {
    fn new(addr: &str) -> Result<Self, anyhow::Error> {
        if let Ok(addr) = addr.parse::<Ipv6Addr>() {
            Ok(Self::Static(u128::from_be_bytes(addr.octets())))
        } else {
            Ok(Self::Dynamic(addr.to_string()))
        }
    }

    async fn resolve(&self) -> Result<u128, anyhow::Error> {
        match self {
            Self::Static(addr) => Ok(*addr),
            Self::Dynamic(addr_str) => {
                let mut addr = tokio::net::lookup_host((addr_str.as_str(), 0)).await?;
                loop {
                    match addr.next() {
                        Some(SocketAddr::V6(sock_addr)) => {
                            return Ok(u128::from_be_bytes(sock_addr.ip().octets()));
                        },

                        None => break,
                        _ => {
                            // Ignore other address types
                        }
                    }
                }
                Err(anyhow::anyhow!("No IPv6 address found for {}", addr_str))
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/etherip-xdp"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { bind_iface, bridged_iface, remote_address } = opt;

    let bind_iface_index = interface::name_to_index(&bind_iface).expect("failed to get interface index").inner_unchecked();
    if bind_iface_index == 0 {
        return Err(anyhow::anyhow!("failed to get interface index for {}: {}", bind_iface, std::io::Error::last_os_error()));
    }

    let bridged_iface_index = interface::name_to_index(&bridged_iface).expect("failed to get interface index").inner_unchecked();
    if bridged_iface_index == 0 {
        return Err(anyhow::anyhow!("failed to get interface index for {}: {}", bridged_iface, std::io::Error::last_os_error()));
    }

    let mut remote_addr_map = std::collections::HashMap::<u16, RemoteAddr>::new();
    remote_addr_map.insert(
        vlan::VLAN_ID_LOCAL,
        RemoteAddr::new(&remote_address).context("failed to parse remote address")?,
    );

    let encap_program: &mut Xdp = ebpf.program_mut("etherip_xdp_encap").unwrap().try_into()?;
    encap_program.load()?;
    encap_program.attach(&bridged_iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let decap_program: &mut Xdp = ebpf.program_mut("etherip_xdp_decap").unwrap().try_into()?;
    decap_program.load()?;
    decap_program.attach(&bind_iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    
    let mut if_indexes = aya::maps::HashMap::<_, u32, u32>::try_from(ebpf.map_mut("IF_INDEX_MAP").unwrap())?;

    if_indexes.insert(iface::IF_INDEX_INNER, bridged_iface_index, 0)?;
    if_indexes.insert(iface::IF_INDEX_OUTER, bind_iface_index, 0)?;


    println!("XDP program loaded and attached to interfaces");

    let rtnl_conn = rtnl::RtnetlinkConnection::new().await?;
    let mut link_manager = rtnl_conn.link();
    let addr_manager = rtnl_conn.address();
    let route_manager = rtnl_conn.route();
    let neigh_manager = rtnl_conn.neighbor();

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            // Insert the local IPv6 address into the map
            let local_if_id = interface::InterfaceId::new(bind_iface_index);
            let local_addr = addr_manager.get_v6(local_if_id, rtnl::addr::V6AddressRequestScope::Global).await?;
            if local_addr.is_empty() {
                log::error!("No global IPv6 address found for interface {}", bind_iface);
                continue;
            }
            let local_addr = local_addr[0];
            let local_addr = ipv6::to_u128(local_addr.octets());
            let mut ipv6_addr_map = aya::maps::HashMap::<_, u16, u128>::try_from(ebpf.map_mut("IPV6_ADDR_MAP").unwrap())?;
            ipv6_addr_map.insert(vlan::VLAN_ID_LOCAL, local_addr, 0)?;
    
            // Get the IPv6 gateway
            let route = route_manager.get_v6(Ipv6Addr::UNSPECIFIED, 0).await?;
            if route.is_empty() {
                log::error!("No IPv6 route found");
                continue;
            }
            let (egress_if_id, gateway_addr) = route[0];
    
            let lladdr = neigh_manager.neigh_get(egress_if_id, std::net::IpAddr::V6(gateway_addr)).await?;
            if lladdr.is_none() {
                log::error!("No link layer address found for gateway {}", gateway_addr);
                continue;
            }
            let lladdr = lladdr.unwrap();
            let lladdr = mac::to_u64((&lladdr as &[u8]).try_into().unwrap());
    
            // Insert the MAC address of the local interface into the map
            let local_mac = link_manager.get_link_layer_address(local_if_id).await?;
            if local_mac.is_none() {
                log::error!("No MAC address found for interface {}", bind_iface);
                continue;
            }
            let local_mac = local_mac.unwrap();
            let local_mac = mac::to_u64((&local_mac as &[u8]).try_into().unwrap());
            let mut mac_addr_map = aya::maps::HashMap::<_, u32, u64>::try_from(ebpf.map_mut("MAC_ADDR_MAP").unwrap())?;
            mac_addr_map.insert(mac::MAC_ADDR_LOCAL, local_mac, 0)?;
            mac_addr_map.insert(mac::MAC_ADDR_GATEWAY, lladdr, 0)?;
    
            for (vlan_id, remote_addr) in remote_addr_map.iter() {
                let addr = remote_addr.resolve().await;
                let addr = if let Ok(addr) = addr {
                    addr
                } else {
                    log::error!("Failed to resolve remote address: {:?}", remote_addr);
                    continue;
                };
                let mut ipv6_addr_map = aya::maps::HashMap::<_, u16, u128>::try_from(ebpf.map_mut("IPV6_ADDR_MAP").unwrap())?;
                ipv6_addr_map.insert(*vlan_id, addr, 0)?;
                let mut vlan_id_map = aya::maps::HashMap::<_, u128, u16>::try_from(ebpf.map_mut("VLAN_ID_MAP").unwrap())?;
                vlan_id_map.insert(addr, *vlan_id, 0)?;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(9)).await;
        }

        #[allow(unreachable_code)]
        Err::<(), _>(anyhow::Error::msg("Unreachable"))
    });
    
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
