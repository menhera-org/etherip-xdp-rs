
use futures::TryStreamExt;

use std::net::Ipv6Addr;

use crate::interface::InterfaceId;

#[allow(dead_code)]
pub struct RouteManager {
    handle: rtnetlink::RouteHandle,
}

impl RouteManager {
    pub(crate) fn new(handle: &super::RtnetlinkConnection) -> Self {
        Self { handle: handle.handle.route() }
    }

    pub async fn get_v6(&self, dst: std::net::Ipv6Addr, prefix_len: u8) -> Result<Vec<(InterfaceId, std::net::Ipv6Addr)>, std::io::Error> {
        let mut routes = Vec::new();
        let req = self.handle.get(rtnetlink::IpVersion::V6);
        let response = req.execute();
        futures::pin_mut!(response);
        while let Some(response) = response.try_next().await.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))? {
            let mut if_index = 0;
            let mut gateway = Ipv6Addr::UNSPECIFIED;
            let mut found = false;
            if response.header.address_family != netlink_packet_route::AddressFamily::Inet6 {
                continue;
            }
            if response.header.destination_prefix_length != prefix_len {
                continue;
            }
            for route in response.attributes.iter() {
                if let netlink_packet_route::route::RouteAttribute::Oif(ifidx) = route {
                    if_index = *ifidx;
                }
                if let netlink_packet_route::route::RouteAttribute::Gateway(addr) = route {
                    gateway = match addr {
                        netlink_packet_route::route::RouteAddress::Inet6(addr) => *addr,
                        _ => Ipv6Addr::UNSPECIFIED,
                    };
                }
                if let netlink_packet_route::route::RouteAttribute::Destination(addr) = route {
                    if let netlink_packet_route::route::RouteAddress::Inet6(addr) = addr {
                        if addr == &dst {
                            found = true;
                        }
                    }
                }
            }

            if prefix_len == 0 && response.header.destination_prefix_length == 0 {
                found = true;
            }

            if found {
                routes.push((InterfaceId::new(if_index), gateway));
            }
        }
        Ok(routes)
    }

}
