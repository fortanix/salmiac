use std::net::{Ipv4Addr, IpAddr};
use rtnetlink::proto::Connection;
use rtnetlink::packet::RtnlMessage;

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