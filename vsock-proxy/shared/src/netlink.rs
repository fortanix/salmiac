use futures::stream::TryStreamExt;
use futures::TryStream;
use rtnetlink::proto::Connection;
use rtnetlink::packet::{RtnlMessage, RouteMessage, NeighbourMessage, LinkMessage, AddressMessage};
use rtnetlink::{IpVersion};

use std::net::{Ipv4Addr, IpAddr};
use ipnetwork::{IpNetwork, Ipv4Network};
use crate::vec_to_ip4;

const FAMILY_INET : u8 = 2;

pub fn connect() -> (Connection<RtnlMessage> , rtnetlink::Handle) {
    let (connection, handle, _) = rtnetlink::new_connection().map_err(|err| format!("{:?}", err)).expect("Failed to connect to netlink");

    (connection, handle)
}

pub async fn get_inet_addresses_for_device(handle : &rtnetlink::Handle, device_index: u32) -> Result<Vec<AddressMessage>, String> {
    let mut links = handle.address()
        .get()
        .set_link_index_filter(device_index)
        .execute();

    let mut result : Vec<AddressMessage> = Vec::new();
    while let Some(link) = next_in_stream(&mut links).await? {
        if link.header.family == FAMILY_INET {
            result.push(link);
        }
    }

    Ok(result)
}

pub async fn get_link_for_device(handle : &rtnetlink::Handle, device_index: u32) -> Result<Option<LinkMessage>, String> {
    let mut links = handle.link()
        .get()
        .match_index(device_index)
        .execute();

    let mut result : Option<LinkMessage> = None;
    while let Some(link) = next_in_stream(&mut links).await? {
        match result {
            None => {
                result = Some(link)
            }
            _ => {
                return Err(format!("Device with index {} should have only one link. Found link: {:?}", device_index, link))
            }
        }
    }

    Ok(result)
}

pub async fn set_link(handle : &rtnetlink::Handle, device_index: u32, mac_address: &[u8; 6]) -> Result<(), String> {
    handle.link()
        .set(device_index)
        .address(mac_address.to_vec())
        .execute()
        .await
        .map_err(|err| format!("Failed to set MAC address {:?}", err))
}

pub async fn add_default_gateway(handle : &rtnetlink::Handle, address : Ipv4Addr) -> Result<(), String> {
    handle.route()
        .add()
        .v4()
        .gateway(address)
        .execute()
        .await
        .map_err(|err| format!("Failed to create default gateway {:?}", err))
}

pub async fn get_default_route_for_device(handle :&rtnetlink::Handle, device_index : u32) -> Result<Option<RouteMessage>, String> {
    let mut routes = handle.route().get(IpVersion::V4).execute();

    while let Some(route) = next_in_stream(&mut routes).await? {
        // default route has no destination or /0 destination
        if route.output_interface() == Some(device_index) &&
            route.destination_prefix().map_or(true, |(_, prefix)| prefix == 0) {
            return Ok(Some(route))
        }
    }

    Ok(None)
}

pub trait AddressMessageExt {
    fn ip_network(&self) -> Result<IpNetwork, String>;

    fn address(&self) -> Option<&[u8]>;
}

impl AddressMessageExt for AddressMessage {

    fn address(&self) -> Option<&[u8]> {
        use rtnetlink::packet::rtnl::address::nlas::Nla;

        self.nlas.iter().find_map(|nla| {
            if let Nla::Address(v) = nla {
                let result : &[u8] = &v;
                Some(result)
            } else {
                None
            }
        })
    }

    fn ip_network(&self) -> Result<IpNetwork, String> {
        let address = self.address()
            .ok_or("Address message must have an address field".to_string())
            .and_then(|e| vec_to_ip4(e))?;

        let result = Ipv4Network::new(address, self.header.prefix_len)
            .map_err(|err| format!("Cannot create ip network {:?}", err))?;

        Ok(IpNetwork::V4(result))
    }
}

pub trait LinkMessageExt {
    fn address(&self) -> Option<&[u8]>;

    fn mtu(&self) -> Option<u32>;
}

impl LinkMessageExt for LinkMessage {
    fn address(&self) -> Option<&[u8]> {
        use rtnetlink::packet::rtnl::link::nlas::Nla;

        self.nlas.iter().find_map(|nla| {
            if let Nla::Address(v) = nla {
                let result : &[u8] = &v;
                Some(result)
            } else {
                None
            }
        })
    }

    fn mtu(&self) -> Option<u32> {
        use rtnetlink::packet::rtnl::link::nlas::Nla;

        self.nlas.iter().find_map(|nla| {
            if let Nla::Mtu(result) = nla {
                Some(*result)
            } else {
                None
            }
        })
    }
}

pub trait RouteMessageExt {
    fn raw_gateway(&self) -> Option<&[u8]>;
}

impl RouteMessageExt for RouteMessage {
    fn raw_gateway(&self) -> Option<&[u8]> {
        use rtnetlink::packet::nlas::route::Nla;

        self.nlas.iter().find_map(|nla| {
            if let Nla::Gateway(v) = nla {
                let result : &[u8] = &v;
                Some(result)
            } else {
                None
            }
        })
    }
}

pub trait NeighbourMessageExt {
    fn link_local_address(&self) -> Option<&[u8]>;

    fn destination(&self) -> Option<&[u8]>;

    fn has_destination_for_address(&self, address : &[u8]) -> bool;
}

impl NeighbourMessageExt for NeighbourMessage {
    fn link_local_address(&self) -> Option<&[u8]> {
        use rtnetlink::packet::neighbour::Nla;

        self.nlas.iter().find_map(|nla| {
            if let Nla::LinkLocalAddress(v) = nla {
                let result : &[u8] = &v;
                Some(result)
            } else {
                None
            }
        })
    }

    fn destination(&self) -> Option<&[u8]> {
        use rtnetlink::packet::neighbour::Nla;

        self.nlas.iter().find_map(|nla| {
            if let Nla::Destination(v) = nla {
                let result : &[u8] = &v;
                Some(result)
            } else {
                None
            }
        })
    }

    fn has_destination_for_address(&self, address : &[u8]) -> bool {
        match self.destination() {
            Some(destination_address) if *destination_address == *address => {
                true
            }
            _ => { false }
        }
    }
}

async fn next_in_stream<T, S>(stream : &mut S) -> Result<Option<T>, String>
    where S : TryStream<Ok = T, Error = rtnetlink::Error> + Unpin {

    stream.try_next()
        .await
        .map_err(|err| format!("Failed to get next item {:?}", err))
}
