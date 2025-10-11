
pub use iphost;
pub use iphost::IpHost;
pub use net_interfaces;
pub use net_interfaces::IfName;
pub use ::vlan as vlan_rs;
pub use ::vlan::MaybeVlanId;

use anyhow::{anyhow, bail, Context as _};
use aya::programs::{Xdp, XdpFlags};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[rustfmt::skip]
use tracing::{debug, info, warn};

use tokio::signal;

use core::net::Ipv6Addr;
use std::collections::HashSet;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use etherip_xdp_common::{iface, ipv6, mac, vlan};
use ftth_rtnl::{AddressScope, Ipv6Net, RtnlClient};

pub mod interface;

#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize), serde(rename_all = "lowercase"))]
pub enum EtheripTransport {
    Ipv4,
    Ipv6,
}

impl Default for EtheripTransport {
    fn default() -> Self {
        Self::Ipv6
    }
}

/// EtherIP tunnel configuration for a particular VLAN / remote pair.
/// 
/// Note that no multiple tunnels can share the same VLAN ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct EtheripTunnelConfig {
    /// VLAN ID on the bridged interface side. Defaults to 0 (native VLAN).
    #[cfg_attr(feature = "serde", serde(default))]
    pub vlan_id: MaybeVlanId,

    /// Transport type to use for this tunnel.
    /// Currently, only 'ipv6' is supported (default).
    #[cfg_attr(feature = "serde", serde(default))]
    pub transport: EtheripTransport,

    /// Remote tunnel endpoint address / FQDN.
    pub remote_addr: IpHost,

    /// Optional description.
    #[cfg_attr(feature = "serde", serde(default))]
    #[allow(unused_attributes)]
    pub description: String,
}

/// EtherIP-XDP server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct EtheripConfig {
    /// The outer interface to transmit encapsulated packets through.
    pub bind_iface: String,

    /// The inner interface to be bridged to our EtherIP tunnels.
    pub bridged_iface: String,

    /// EtherIP tunnel definitions.
    #[cfg_attr(feature = "serde", serde(rename = "tunnel"))]
    pub tunnels: Vec<EtheripTunnelConfig>,
}

impl EtheripConfig {
    pub fn is_valid(&self) -> bool {
        let mut found_vlan_set = HashSet::new();
        for tunnel in self.tunnels.iter() {
            if found_vlan_set.contains(&tunnel.vlan_id) {
                return false;
            }
            found_vlan_set.insert(tunnel.vlan_id);
        }
        true
    }
}

async fn call_blocking_io<F, R, E>(f: F) -> io::Result<R>
where
    F: FnOnce() -> Result<R, E> + Send + 'static,
    R: Send + 'static,
    E: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map(|r| r.map_err(io::Error::other))
        .map_err(io::Error::other).flatten()
}

pub async fn run(opt: EtheripConfigOld) -> anyhow::Result<()> {
    let EtheripConfigOld {
        bind_iface,
        bridged_iface,
        tunnels,
    } = opt;

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
    #[cfg(feature = "build-ebpf")]
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/etherip-xdp"
    )))?;

    #[cfg(not(feature = "build-ebpf"))]
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/etherip-xdp"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let bind_iface_id = interface::name_to_index(&bind_iface)
        .with_context(|| format!("failed to get interface index for {bind_iface}"))?;
    let bind_iface_index = bind_iface_id
        .inner()
        .ok_or_else(|| anyhow!("interface index for {bind_iface} is unspecified"))?;

    let bridged_iface_id = interface::name_to_index(&bridged_iface)
        .with_context(|| format!("failed to get interface index for {bridged_iface}"))?;
    let bridged_iface_index = bridged_iface_id
        .inner()
        .ok_or_else(|| anyhow!("interface index for {bridged_iface} is unspecified"))?;

    let mut tunnel_configs = Vec::with_capacity(tunnels.len());
    let mut seen_vlans = HashSet::with_capacity(tunnels.len());

    for config in tunnels {
        if !seen_vlans.insert(config.vlan_id) {
            bail!("duplicate tunnel configuration for VLAN {}", config.vlan_id);
        }
        tunnel_configs.push(config);
    }

    if !seen_vlans.contains(&vlan::VLAN_ID_NATIVE) {
        info!("no native VLAN tunnel configured; untagged frames remain on the bridged interface");
    }

    let tunnels = tunnel_configs;

    let encap_program: &mut Xdp = ebpf
        .program_mut("etherip_xdp_encap")
        .ok_or_else(|| anyhow!("eBPF program etherip_xdp_encap not found"))?
        .try_into()?;
    encap_program.load()?;
    encap_program.attach(&bridged_iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let decap_program: &mut Xdp = ebpf
        .program_mut("etherip_xdp_decap")
        .ok_or_else(|| anyhow!("eBPF program etherip_xdp_decap not found"))?
        .try_into()?;
    decap_program.load()?;
    decap_program.attach(&bind_iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut if_indexes = aya::maps::HashMap::<_, u32, u32>::try_from(
        ebpf.map_mut("IF_INDEX_MAP")
            .ok_or_else(|| anyhow!("IF_INDEX_MAP not found"))?,
    )?;

    if_indexes.insert(iface::IF_INDEX_INNER, bridged_iface_index, 0)?;
    if_indexes.insert(iface::IF_INDEX_OUTER, bind_iface_index, 0)?;

    info!("XDP program loaded and attached to interfaces");

    let rtnl = RtnlClient::new();
    let link_client = rtnl.link();
    let address_client = rtnl.address();
    let route_client = rtnl.route();
    let neighbor_client = rtnl.neighbor();
    let default_ipv6_route_prefix =
        Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).map_err(|err| anyhow!(err))?;
    let tunnels_task = tunnels.clone();
    let bind_iface_task = bind_iface.clone();
    let bind_iface_id_task = bind_iface_id;

    tokio::spawn(async move {
        let mut ebpf = ebpf;
        let tunnels = tunnels_task;
        let bind_iface = bind_iface_task;
        let address_client = address_client;
        let route_client = route_client;
        let neighbor_client = neighbor_client;
        let link_client = link_client;
        let default_route_prefix = default_ipv6_route_prefix;
        let bind_iface_id = bind_iface_id_task;

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

            let local_if_id = bind_iface_id;
            let Some(local_if_index) = local_if_id.inner() else {
                tracing::error!("local interface index became unspecified");
                continue;
            };

            let local_addrs = call_blocking_io({
                let address_client = address_client.clone();
                move || {
                    address_client.ipv6_addrs_get_with_scope(
                        Some(local_if_index),
                        Some(AddressScope::Universe),
                    )
                }
            })
            .await?;
            if local_addrs.is_empty() {
                tracing::error!("No global IPv6 address found for interface {}", bind_iface);
                continue;
            }
            let local_addr = local_addrs[0];
            let local_addr = ipv6::to_u128(local_addr.octets());
            let mut ipv6_addr_map = aya::maps::HashMap::<_, u16, u128>::try_from(
                ebpf.map_mut("IPV6_ADDR_MAP")
                    .ok_or_else(|| anyhow!("IPV6_ADDR_MAP not found"))?,
            )?;
            ipv6_addr_map.insert(vlan::VLAN_ID_LOCAL, local_addr, 0)?;

            let route = match call_blocking_io({
                let route_client = route_client.clone();
                move || route_client.ipv6_route_get_by_prefix(default_route_prefix)
            })
            .await
            {
                Ok(route) => route,
                Err(err) if err.kind() == ErrorKind::NotFound => {
                    tracing::error!("No IPv6 route found");
                    continue;
                }
                Err(err) => {
                    tracing::error!("Failed to retrieve IPv6 default route: {}", err);
                    continue;
                }
            };

            let egress_if_index = route
                .if_id
                .or_else(|| route.nexthops.iter().find_map(|hop| hop.if_id));
            let egress_if_index = match egress_if_index {
                Some(index) if index != 0 => index,
                _ => {
                    tracing::error!("No egress interface found for default IPv6 route");
                    continue;
                }
            };
            let gateway_addr = route
                .gateway
                .and_then(|gw| match gw {
                    IpAddr::V6(addr) => Some(addr),
                    _ => None,
                })
                .or_else(|| {
                    route.nexthops.iter().find_map(|hop| {
                        hop.gateway.and_then(|gw| match gw {
                            IpAddr::V6(addr) => Some(addr),
                            _ => None,
                        })
                    })
                });
            let gateway_addr = match gateway_addr {
                Some(addr) => addr,
                None => {
                    tracing::error!("No IPv6 gateway found for default route");
                    continue;
                }
            };
            tracing::debug!(
                "Egress interface ID: {}, Gateway address: {}",
                egress_if_index,
                gateway_addr
            );

            let gateway_entry = match call_blocking_io({
                let neighbor_client = neighbor_client.clone();
                move || neighbor_client.get(IpAddr::V6(gateway_addr), Some(egress_if_index))
            })
            .await
            {
                Ok(entry) => entry,
                Err(err) if err.kind() == ErrorKind::NotFound => {
                    tracing::error!("No link layer address found for gateway {}", gateway_addr);
                    continue;
                }
                Err(err) => {
                    tracing::error!(
                        "Failed to resolve neighbor entry for gateway {}: {}",
                        gateway_addr,
                        err
                    );
                    continue;
                }
            };

            let lladdr_bytes: [u8; 6] = match gateway_entry.link_address {
                Some(addr) => match addr.as_slice().try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        tracing::error!(
                            "Unexpected link layer address length for gateway {}",
                            gateway_addr
                        );
                        continue;
                    }
                },
                None => {
                    tracing::error!("No link layer address found for gateway {}", gateway_addr);
                    continue;
                }
            };
            tracing::debug!("Gateway's link layer address: {:?}", lladdr_bytes);
            let lladdr = mac::to_u64(&lladdr_bytes);

            let local_mac = call_blocking_io({
                let link_client = link_client.clone();
                move || link_client.mac_addr_get(local_if_index)
            })
            .await?;
            let local_mac = match local_mac {
                Some(mac) => mac.inner,
                None => {
                    tracing::error!("No MAC address found for interface {}", bind_iface);
                    continue;
                }
            };
            tracing::debug!("Local MAC address: {:?}", local_mac);
            let local_mac = mac::to_u64(&local_mac);
            let mut mac_addr_map = aya::maps::HashMap::<_, u32, u64>::try_from(
                ebpf.map_mut("MAC_ADDR_MAP")
                    .ok_or_else(|| anyhow!("MAC_ADDR_MAP not found"))?,
            )?;
            mac_addr_map.insert(mac::MAC_ADDR_LOCAL, local_mac, 0)?;
            mac_addr_map.insert(mac::MAC_ADDR_GATEWAY, lladdr, 0)?;

            for tunnel in &tunnels {
                let addr = match tunnel.remote.resolve().await {
                    Ok(addr) => addr,
                    Err(err) => {
                        tracing::error!(
                            "Failed to resolve remote address for VLAN {}: {}",
                            tunnel.vlan_id,
                            err
                        );
                        continue;
                    }
                };
                tracing::debug!(
                    "Resolved remote address for VLAN {}: {}",
                    tunnel.vlan_id,
                    Ipv6Addr::from(addr)
                );
                let mut ipv6_addr_map = aya::maps::HashMap::<_, u16, u128>::try_from(
                    ebpf.map_mut("IPV6_ADDR_MAP")
                        .ok_or_else(|| anyhow!("IPV6_ADDR_MAP not found"))?,
                )?;
                ipv6_addr_map.insert(tunnel.vlan_id, addr, 0)?;
                let mut vlan_id_map = aya::maps::HashMap::<_, u128, u16>::try_from(
                    ebpf.map_mut("VLAN_ID_MAP")
                        .ok_or_else(|| anyhow!("VLAN_ID_MAP not found"))?,
                )?;
                vlan_id_map.insert(addr, tunnel.vlan_id, 0)?;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(9)).await;
        }

        #[allow(unreachable_code)]
        Err::<(), _>(anyhow::Error::msg("Unreachable"))
    });

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    Ok(())
}
