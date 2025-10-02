use futures::TryStreamExt;

use crate::interface::InterfaceId;

#[allow(dead_code)]
pub struct NeighborManager {
    handle: rtnetlink::NeighbourHandle,
}

impl NeighborManager {
    pub(crate) fn new(handle: &super::RtnetlinkConnection) -> Self {
        Self {
            handle: handle.handle.neighbours(),
        }
    }

    pub async fn neigh_get(
        &self,
        if_id: InterfaceId,
        addr: std::net::IpAddr,
    ) -> Result<Option<Vec<u8>>, std::io::Error> {
        let mut neigh_msg = netlink_packet_route::neighbour::NeighbourMessage::default();
        neigh_msg.header.family = match addr {
            std::net::IpAddr::V4(_) => netlink_packet_route::AddressFamily::Inet,
            std::net::IpAddr::V6(_) => netlink_packet_route::AddressFamily::Inet6,
        };
        neigh_msg.attributes.push(
            netlink_packet_route::neighbour::NeighbourAttribute::Destination(match addr {
                std::net::IpAddr::V4(v4) => {
                    netlink_packet_route::neighbour::NeighbourAddress::Inet(v4)
                }
                std::net::IpAddr::V6(v6) => {
                    netlink_packet_route::neighbour::NeighbourAddress::Inet6(v6)
                }
            }),
        );
        neigh_msg.header.ifindex = if_id.inner_unchecked();
        let mut req = self.handle.get();
        *(req.message_mut()) = neigh_msg;
        let response = req.execute();
        futures::pin_mut!(response);
        while let Some(response) = response
            .try_next()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        {
            for neigh in response.attributes.iter() {
                if let netlink_packet_route::neighbour::NeighbourAttribute::LinkLocalAddress(addr) =
                    neigh
                {
                    if addr == &[0, 0, 0, 0, 0, 0] {
                        continue;
                    }
                    return Ok(Some(addr.clone()));
                }
            }
        }
        Ok(None)
    }
}
