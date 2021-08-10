use std::net::{Ipv4Addr, IpAddr};
use futures::stream::TryStreamExt;
use rtnetlink::proto::Connection;
use rtnetlink::packet::{RtnlMessage, RouteMessage, NeighbourMessage};
use rtnetlink::{IpVersion};
use rtnetlink::packet::neighbour::Nla::Destination;

pub fn connect() -> (Connection<RtnlMessage> , rtnetlink::Handle) {
    let (connection, handle, _) = rtnetlink::new_connection().map_err(|err| format!("{:?}", err)).expect("Failed to connect to netlink");

    (connection, handle)
}

pub async fn set_address(handle : &rtnetlink::Handle, index : u32, address : Vec<u8>) -> Result<(), String> {
    handle.link()
        .set(index)
        .address(address)
        .execute()
        .await
        .map_err(|err| format!("Failed to set MAC address {:?}", err))
}

pub async fn add_neighbour(handle : &rtnetlink::Handle, device_index : u32, destination : IpAddr, mac : Vec<u8>) -> Result<(), String> {
    handle.neighbours()
        .add(device_index, destination)
        .link_local_address(&mac)
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

    while let Some(route) = routes.try_next().await.map_err(|err| format!("Failed to get next item {:?}", err))? {
        println!("Route: {:?}", route);
        match route.output_interface() {
            Some(index) if route.gateway().is_some() && index == device_index => {
                return Ok(Some(route))
            }
            _ => {}
        }
    }

    Ok(None)
}

pub async fn get_neighbour_for_device(handle : &rtnetlink::Handle, device_index : u32, gateway_address : Vec<u8>) -> Result<Option<NeighbourMessage>, String> {
    fn destination(neighbour : &NeighbourMessage) -> Option<Vec<u8>> {
        neighbour.nlas.iter().find_map(|nla| {
            if let Destination(v) = nla {
                Some(v.clone())
            } else {
                None
            }
        })
    }

    let mut neighbours = handle.neighbours().get().execute();

    while let Some(neighbour) = neighbours.try_next().await.map_err(|err| format!("Failed to get next item {:?}", err))? {
        println!("ARP: {:?}", neighbour);
        if neighbour.header.ifindex == device_index {
            match destination(&neighbour) {
                Some(address) if address == gateway_address => {
                    return Ok(Some(neighbour))
                }
                _ => {}
            }
        }
    }

    Ok(None)
}