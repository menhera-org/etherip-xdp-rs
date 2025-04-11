
use crate::interface::InterfaceId;

use futures::TryStreamExt;

#[derive(Debug, Clone, Copy)]
pub enum V6AddressRequestScope {
    Global,
    LinkLocal,
}

#[allow(dead_code)]
pub struct AddressManager {
    handle: rtnetlink::AddressHandle,
}

impl AddressManager {
    pub(crate) fn new(handle: &super::RtnetlinkConnection) -> Self {
        Self { handle: handle.handle.address() }
    }

    pub async fn get_v6(&self, if_index: InterfaceId, scope: V6AddressRequestScope) -> Result<Vec<std::net::Ipv6Addr>, std::io::Error> {
        let if_index = if_index.inner_unchecked();
        log::debug!("get_v6: if_index={}, scope={:?}", if_index, scope);
        let mut addrs = Vec::new();
        let mut req = self.handle.get();
        if if_index != 0 {
            req = req.set_link_index_filter(if_index);
        }
        let response = req.execute();

        futures::pin_mut!(response);
        while let Some(response) = response.try_next().await.map_err(|e| std::io::Error::other(e))? {
            if response.header.family != netlink_packet_route::AddressFamily::Inet6 {
                continue;
            }
            if response.header.scope != match scope {
                V6AddressRequestScope::Global => netlink_packet_route::address::AddressScope::Universe,
                V6AddressRequestScope::LinkLocal => netlink_packet_route::address::AddressScope::Link,
            } {
                continue;
            }
            for addr in response.attributes.iter() {
                if let netlink_packet_route::address::AddressAttribute::Address(std::net::IpAddr::V6(addr)) = addr {
                    log::debug!("found address: {}", addr);
                    addrs.push(*addr);
                }
            }
        }
        Ok(addrs)
    }
}
