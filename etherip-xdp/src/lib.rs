use anyhow::{anyhow, bail, Context as _};
use aya::programs::{Xdp, XdpFlags};

#[cfg(feature = "clap")]
use clap::Parser;

#[rustfmt::skip]
use log::{debug, info, warn};

use tokio::signal;

use core::net::Ipv6Addr;
use std::collections::HashSet;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};

use etherip_xdp_common::{iface, ipv6, mac, vlan};
use ftth_rtnl::{AddressScope, Ipv6Net, RtnlClient};

pub mod interface;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "clap", derive(Parser))]
#[cfg_attr(feature = "clap", clap(rename_all = "kebab-case"))]
/// A simple XDP program that encapsulates and decapsulates packets using EtherIP.
pub struct Opt {
    /// The outer interface to transmit encapsulated packets.
    #[cfg_attr(feature = "clap", clap(short = 'o', long, default_value = "eth0"))]
    pub bind_iface: String,

    /// The inner interface to be bridged by the EtherIP tunnel.
    #[cfg_attr(feature = "clap", clap(short = 'i', long, default_value = "eth1"))]
    pub bridged_iface: String,

    /// Tunnel definitions mapping VLAN IDs to remote endpoints.
    #[cfg_attr(feature = "clap", clap(
        long = "tunnel",
        value_parser = TunnelSpec::parse,
        default_value = "remote=::1"
    ))]
    pub tunnels: Vec<TunnelConfig>,
}

/// Note that we currently only support IPv6 addresses.
#[derive(Debug, Clone)]
pub enum RemoteAddr {
    StaticIpv6(u128),
    Dynamic(String),
}

impl RemoteAddr {
    pub fn ipv6_address(addr: Ipv6Addr) -> Self {
        Self::StaticIpv6(u128::from_be_bytes(addr.octets()))
    }

    pub fn new(addr: &str) -> Self {
        if let Ok(addr) = addr.parse::<Ipv6Addr>() {
            Self::ipv6_address(addr)
        } else {
            Self::Dynamic(addr.to_string())
        }
    }

    async fn resolve(&self) -> Result<u128, anyhow::Error> {
        match self {
            Self::StaticIpv6(addr) => Ok(*addr),
            Self::Dynamic(addr_str) => {
                let mut addr = tokio::net::lookup_host((addr_str.as_str(), 0)).await?;
                loop {
                    match addr.next() {
                        Some(SocketAddr::V6(sock_addr)) => {
                            return Ok(u128::from_be_bytes(sock_addr.ip().octets()));
                        }

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

async fn call_blocking_io<F, R>(f: F) -> io::Result<R>
where
    F: FnOnce() -> io::Result<R> + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| io::Error::new(ErrorKind::Other, err))?
}

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub vlan_id: u16,
    pub remote: RemoteAddr,
}

impl TunnelConfig {
    pub fn new(vlan_id: Option<u16>, remote: &str) -> anyhow::Result<Self> {
        TunnelSpec::new(vlan_id, remote.to_owned()).into_config()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TunnelSpec {
    pub vlan_id: Option<u16>,
    pub remote: String,
}

impl TunnelSpec {
    pub(crate) fn new(vlan_id: Option<u16>, remote: String) -> Self {
        Self { vlan_id, remote }
    }

    #[cfg(feature = "clap")]
    fn parse(raw: &str) -> Result<TunnelConfig, anyhow::Error> {
        let raw = raw.trim();
        if raw.is_empty() {
            bail!("tunnel definition must not be empty");
        }

        let mut remote = None;
        let mut vlan = None;

        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let mut kv = part.splitn(2, '=');
            let key = kv
                .next()
                .map(str::trim)
                .ok_or_else(|| anyhow!("malformed tunnel definition"))?;
            if let Some(value) = kv.next() {
                let value = value.trim();
                match key {
                    "remote" => {
                        if remote.is_some() {
                            bail!("duplicate remote entry in tunnel definition");
                        }
                        if value.is_empty() {
                            bail!("remote address must not be empty");
                        }
                        remote = Some(value.to_string());
                    }
                    "vlan" => {
                        if vlan.is_some() {
                            bail!("duplicate vlan entry in tunnel definition");
                        }
                        let parsed = value
                            .parse::<u16>()
                            .map_err(|err| anyhow!("invalid VLAN id '{value}': {err}"))?;
                        vlan = Some(parsed);
                    }
                    _ => {
                        bail!("unknown tunnel option '{key}'");
                    }
                }
            } else {
                if remote.is_none() {
                    if key.is_empty() {
                        bail!("remote address must not be empty");
                    }
                    remote = Some(key.to_string());
                } else {
                    bail!("unexpected tunnel value '{part}'");
                }
            }
        }

        let remote = remote.ok_or_else(|| anyhow!("remote address is required for tunnel"))?;

        Self {
            vlan_id: vlan,
            remote,
        }
        .into_config()
    }

    pub fn into_config(self) -> anyhow::Result<TunnelConfig> {
        let vlan_id = self.vlan_id.unwrap_or(vlan::VLAN_ID_NATIVE);
        if vlan_id != vlan::VLAN_ID_NATIVE && vlan_id > vlan::VLAN_ID_MAX {
            bail!(
                "VLAN ID {vlan_id} is out of supported range {}..{}",
                vlan::VLAN_ID_MIN,
                vlan::VLAN_ID_MAX
            );
        }
        if vlan_id == vlan::VLAN_ID_LOCAL {
            bail!("VLAN ID {vlan_id} is reserved for local addressing");
        }

        let remote = RemoteAddr::new(&self.remote);
        Ok(TunnelConfig { vlan_id, remote })
    }
}

pub async fn run(opt: Opt) -> anyhow::Result<()> {
    let Opt {
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
                log::error!("local interface index became unspecified");
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
                log::error!("No global IPv6 address found for interface {}", bind_iface);
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
                    log::error!("No IPv6 route found");
                    continue;
                }
                Err(err) => {
                    log::error!("Failed to retrieve IPv6 default route: {}", err);
                    continue;
                }
            };

            let egress_if_index = route
                .if_id
                .or_else(|| route.nexthops.iter().find_map(|hop| hop.if_id));
            let egress_if_index = match egress_if_index {
                Some(index) if index != 0 => index,
                _ => {
                    log::error!("No egress interface found for default IPv6 route");
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
                    log::error!("No IPv6 gateway found for default route");
                    continue;
                }
            };
            log::debug!(
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
                    log::error!("No link layer address found for gateway {}", gateway_addr);
                    continue;
                }
                Err(err) => {
                    log::error!(
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
                        log::error!(
                            "Unexpected link layer address length for gateway {}",
                            gateway_addr
                        );
                        continue;
                    }
                },
                None => {
                    log::error!("No link layer address found for gateway {}", gateway_addr);
                    continue;
                }
            };
            log::debug!("Gateway's link layer address: {:?}", lladdr_bytes);
            let lladdr = mac::to_u64(&lladdr_bytes);

            let local_mac = call_blocking_io({
                let link_client = link_client.clone();
                move || link_client.mac_addr_get(local_if_index)
            })
            .await?;
            let local_mac = match local_mac {
                Some(mac) => mac.inner,
                None => {
                    log::error!("No MAC address found for interface {}", bind_iface);
                    continue;
                }
            };
            log::debug!("Local MAC address: {:?}", local_mac);
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
                        log::error!(
                            "Failed to resolve remote address for VLAN {}: {}",
                            tunnel.vlan_id,
                            err
                        );
                        continue;
                    }
                };
                log::debug!(
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
