use futures::stream::TryStreamExt;
use futures::TryStream;
use rtnetlink::proto::Connection;
use rtnetlink::packet::{RtnlMessage, RouteMessage, NeighbourMessage};
use rtnetlink::{IpVersion};

use std::net::{Ipv4Addr, IpAddr};

pub fn connect() -> (Connection<RtnlMessage> , rtnetlink::Handle) {
    let (connection, handle, _) = rtnetlink::new_connection().map_err(|err| format!("{:?}", err)).expect("Failed to connect to netlink");

    (connection, handle)
}

pub async fn set_address(handle : &rtnetlink::Handle, index : u32, mac_address: &[u8; 6]) -> Result<(), String> {
    handle.link()
        .set(index)
        .address(mac_address.to_vec())
        .execute()
        .await
        .map_err(|err| format!("Failed to set MAC address {:?}", err))
}

pub async fn add_neighbour(handle : &rtnetlink::Handle, device_index : u32, destination : IpAddr, mac_address : &[u8; 6]) -> Result<(), String> {
    handle.neighbours()
        .add(device_index, destination)
        .link_local_address(mac_address)
        .execute()
        .await
        .map_err(|err| format!("Failed to create ARP entry {:?}", err))
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

pub async fn get_route_for_device(handle :&rtnetlink::Handle, device_index : u32) -> Result<Option<RouteMessage>, String> {
    let mut routes = handle.route().get(IpVersion::V4).execute();

    while let Some(route) = next_in_stream(&mut routes).await? {
        match route.output_interface() {
            Some(index) if route.gateway().is_some() && index == device_index => {
                return Ok(Some(route))
            }
            _ => {}
        }
    }

    Ok(None)
}

pub async fn get_neighbour_for_device(handle : &rtnetlink::Handle, device_index : u32, gateway_address : &[u8]) -> Result<Option<NeighbourMessage>, String> {
    let mut neighbours = handle.neighbours().get().execute();

    while let Some(neighbour) = next_in_stream(&mut neighbours).await? {

        if neighbour.header.ifindex == device_index &&
           neighbour.has_destination_for_address(&gateway_address) {

            return Ok(Some(neighbour))
        }
    }

    Ok(None)
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