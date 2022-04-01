pub mod arp;
pub mod route;

use futures::stream::TryStreamExt;
use futures::TryStream;
use ipnetwork::{IpNetwork, Ipv4Network};
use rtnetlink::packet::{AddressMessage, LinkMessage, RtnlMessage};
use rtnetlink::proto::Connection;

use crate::find_map;
use crate::vec_to_ip4;

use std::ops::Deref;

const FAMILY_INET: u8 = 2;

pub fn connect() -> (Connection<RtnlMessage>, rtnetlink::Handle) {
    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|err| format!("{:?}", err))
        .expect("Failed to connect to netlink");

    (connection, handle)
}

pub async fn get_inet_addresses_for_device(
    handle: &rtnetlink::Handle,
    device_index: u32,
) -> Result<Vec<AddressMessage>, String> {
    let mut links = handle.address().get().set_link_index_filter(device_index).execute();

    let mut result: Vec<AddressMessage> = Vec::new();
    while let Some(link) = next_in_stream(&mut links).await? {
        if link.header.family == FAMILY_INET {
            result.push(link);
        }
    }

    Ok(result)
}

pub async fn get_link_for_device(handle: &rtnetlink::Handle, device_index: u32) -> Result<Option<LinkMessage>, String> {
    let mut links = handle.link().get().match_index(device_index).execute();

    let mut result: Option<LinkMessage> = None;
    while let Some(link) = next_in_stream(&mut links).await? {
        match result {
            None => result = Some(link),
            _ => {
                return Err(format!(
                    "Device with index {} should have only one link. Found link: {:?}",
                    device_index, link
                ))
            }
        }
    }

    Ok(result)
}

pub async fn set_link(handle: &rtnetlink::Handle, device_index: u32, mac_address: &[u8; 6]) -> Result<(), String> {
    handle
        .link()
        .set(device_index)
        .address(mac_address.to_vec())
        .execute()
        .await
        .map_err(|err| format!("Failed to set MAC address {:?}", err))
}

pub trait AddressMessageExt {
    fn ip_network(&self) -> Result<IpNetwork, String>;

    fn address(&self) -> Option<&[u8]>;
}

impl AddressMessageExt for AddressMessage {
    fn ip_network(&self) -> Result<IpNetwork, String> {
        let address = self
            .address()
            .ok_or("Address message must have an address field".to_string())
            .and_then(|e| vec_to_ip4(e))?;

        let result =
            Ipv4Network::new(address, self.header.prefix_len).map_err(|err| format!("Cannot create ip network {:?}", err))?;

        Ok(IpNetwork::V4(result))
    }

    fn address(&self) -> Option<&[u8]> {
        use rtnetlink::packet::rtnl::address::nlas::Nla;

        find_map!(&self.nlas, Nla::Address(v) => v.deref())
    }
}

pub trait LinkMessageExt {
    fn address(&self) -> Option<&[u8]>;

    fn mtu(&self) -> Option<u32>;
}

impl LinkMessageExt for LinkMessage {
    fn address(&self) -> Option<&[u8]> {
        use rtnetlink::packet::rtnl::link::nlas::Nla;

        find_map!(&self.nlas, Nla::Address(v) => v.deref())
    }

    fn mtu(&self) -> Option<u32> {
        use rtnetlink::packet::rtnl::link::nlas::Nla;

        find_map!(&self.nlas, Nla::Mtu(result) => *result)
    }
}

async fn next_in_stream<T, S>(stream: &mut S) -> Result<Option<T>, String>
where
    S: TryStream<Ok = T, Error = rtnetlink::Error> + Unpin,
{
    stream
        .try_next()
        .await
        .map_err(|err| format!("Failed to get next item {:?}", err))
}
