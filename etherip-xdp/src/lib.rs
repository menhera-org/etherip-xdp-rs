use anyhow::{bail, Context as _};
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, info, warn};
use tokio::signal;

use core::net::Ipv6Addr;
use std::collections::HashSet;
use std::net::SocketAddr;

use etherip_xdp_common::{iface, ipv6, mac, vlan};

pub mod interface;
pub mod rtnl;

#[derive(Debug, Parser)]
#[clap(rename_all = "kebab-case")]
/// A simple XDP program that encapsulates and decapsulates packets using EtherIP.
pub struct Opt {
    /// The outer interface to transmit encapsulated packets.
    #[clap(short = 'o', long, default_value = "eth0")]
    bind_iface: String,

    /// The inner interface to be bridged by the EtherIP tunnel.
    #[clap(short = 'i', long, default_value = "eth1")]
    bridged_iface: String,

    /// Tunnel definitions mapping VLAN IDs to remote endpoints.
    #[clap(
        long = "tunnel",
        value_parser = TunnelSpec::parse,
        default_value = "remote=::1"
    )]
    tunnels: Vec<TunnelSpec>,
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

#[derive(Debug, Clone)]
struct TunnelConfig {
    vlan_id: u16,
    remote: RemoteAddr,
}

#[derive(Debug, Clone)]
struct TunnelSpec {
    vlan_id: Option<u16>,
    remote: String,
}

impl TunnelSpec {
    fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err("tunnel definition must not be empty".to_string());
        }

        let mut remote = None;
        let mut vlan = None;

        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let mut kv = part.splitn(2, '=');
            let key = kv.next().unwrap().trim();
            if let Some(value) = kv.next() {
                let value = value.trim();
                match key {
                    "remote" => {
                        if remote.is_some() {
                            return Err("duplicate remote entry in tunnel definition".to_string());
                        }
                        if value.is_empty() {
                            return Err("remote address must not be empty".to_string());
                        }
                        remote = Some(value.to_string());
                    }
                    "vlan" => {
                        if vlan.is_some() {
                            return Err("duplicate vlan entry in tunnel definition".to_string());
                        }
                        let parsed = value
                            .parse::<u16>()
                            .map_err(|err| format!("invalid VLAN id '{value}': {err}"))?;
                        vlan = Some(parsed);
                    }
                    _ => {
                        return Err(format!("unknown tunnel option '{key}'"));
                    }
                }
            } else {
                if remote.is_none() {
                    if key.is_empty() {
                        return Err("remote address must not be empty".to_string());
                    }
                    remote = Some(key.to_string());
                } else {
                    return Err(format!("unexpected tunnel value '{part}'"));
                }
            }
        }

        let remote = remote.ok_or_else(|| "remote address is required for tunnel".to_string())?;

        Ok(Self {
            vlan_id: vlan,
            remote,
        })
    }

    fn into_config(self) -> anyhow::Result<TunnelConfig> {
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

        let remote = RemoteAddr::new(&self.remote).context("failed to parse remote address")?;
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

    let bind_iface_index = interface::name_to_index(&bind_iface)
        .expect("failed to get interface index")
        .inner_unchecked();
    if bind_iface_index == 0 {
        return Err(anyhow::anyhow!(
            "failed to get interface index for {}: {}",
            bind_iface,
            std::io::Error::last_os_error()
        ));
    }

    let bridged_iface_index = interface::name_to_index(&bridged_iface)
        .expect("failed to get interface index")
        .inner_unchecked();
    if bridged_iface_index == 0 {
        return Err(anyhow::anyhow!(
            "failed to get interface index for {}: {}",
            bridged_iface,
            std::io::Error::last_os_error()
        ));
    }

    let mut tunnel_configs = Vec::with_capacity(tunnels.len());
    let mut seen_vlans = HashSet::with_capacity(tunnels.len());

    for spec in tunnels {
        let config = spec.into_config()?;
        if !seen_vlans.insert(config.vlan_id) {
            bail!("duplicate tunnel configuration for VLAN {}", config.vlan_id);
        }
        tunnel_configs.push(config);
    }

    if !seen_vlans.contains(&vlan::VLAN_ID_NATIVE) {
        info!("no native VLAN tunnel configured; untagged frames remain on the bridged interface");
    }

    let tunnels = tunnel_configs;

    let encap_program: &mut Xdp = ebpf.program_mut("etherip_xdp_encap").unwrap().try_into()?;
    encap_program.load()?;
    encap_program.attach(&bridged_iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let decap_program: &mut Xdp = ebpf.program_mut("etherip_xdp_decap").unwrap().try_into()?;
    decap_program.load()?;
    decap_program.attach(&bind_iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut if_indexes =
        aya::maps::HashMap::<_, u32, u32>::try_from(ebpf.map_mut("IF_INDEX_MAP").unwrap())?;

    if_indexes.insert(iface::IF_INDEX_INNER, bridged_iface_index, 0)?;
    if_indexes.insert(iface::IF_INDEX_OUTER, bind_iface_index, 0)?;

    info!("XDP program loaded and attached to interfaces");

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
            let local_addr = addr_manager
                .get_v6(local_if_id, rtnl::addr::V6AddressRequestScope::Global)
                .await?;
            if local_addr.is_empty() {
                log::error!("No global IPv6 address found for interface {}", bind_iface);
                continue;
            }
            let local_addr = local_addr[0];
            let local_addr = ipv6::to_u128(local_addr.octets());
            let mut ipv6_addr_map = aya::maps::HashMap::<_, u16, u128>::try_from(
                ebpf.map_mut("IPV6_ADDR_MAP").unwrap(),
            )?;
            ipv6_addr_map.insert(vlan::VLAN_ID_LOCAL, local_addr, 0)?;

            // Get the IPv6 gateway
            let route = route_manager.get_v6(Ipv6Addr::UNSPECIFIED, 0).await?;
            if route.is_empty() {
                log::error!("No IPv6 route found");
                continue;
            }
            let (egress_if_id, gateway_addr) = route[0];
            log::debug!(
                "Egress interface ID: {}, Gateway address: {}",
                egress_if_id.inner_unchecked(),
                gateway_addr
            );

            let lladdr = neigh_manager
                .neigh_get(egress_if_id, std::net::IpAddr::V6(gateway_addr))
                .await?;
            if lladdr.is_none() {
                log::error!("No link layer address found for gateway {}", gateway_addr);
                continue;
            }
            let lladdr = lladdr.unwrap();
            log::debug!("Gateway's link layer address: {:?}", lladdr);
            let lladdr = mac::to_u64((&lladdr as &[u8]).try_into().unwrap());

            // Insert the MAC address of the local interface into the map
            let local_mac = link_manager.get_link_layer_address(local_if_id).await?;
            if local_mac.is_none() {
                log::error!("No MAC address found for interface {}", bind_iface);
                continue;
            }
            let local_mac = local_mac.unwrap();
            log::debug!("Local MAC address: {:?}", local_mac);
            let local_mac = mac::to_u64((&local_mac as &[u8]).try_into().unwrap());
            let mut mac_addr_map =
                aya::maps::HashMap::<_, u32, u64>::try_from(ebpf.map_mut("MAC_ADDR_MAP").unwrap())?;
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
                    ebpf.map_mut("IPV6_ADDR_MAP").unwrap(),
                )?;
                ipv6_addr_map.insert(tunnel.vlan_id, addr, 0)?;
                let mut vlan_id_map = aya::maps::HashMap::<_, u128, u16>::try_from(
                    ebpf.map_mut("VLAN_ID_MAP").unwrap(),
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
