/*use crate::net::device::NetworkSettings;
use crate::net::netlink;

use std::convert::TryInto;
use pnet_datalink::NetworkInterface;

#[tokio::main]
async fn get_network_settings(parent_device : &NetworkInterface) -> Result<NetworkSettings, String> {
    let (_netlink_connection, netlink_handle) = netlink::connect();
    tokio::spawn(_netlink_connection);

    debug!("Connected to netlink");

    let parent_gateway = netlink::get_route_for_device(&netlink_handle, parent_device.index).await?.unwrap();

    let parent_gateway_address = raw_gateway(&parent_gateway).unwrap();

    let parent_arp = netlink::get_neighbour_for_device(&netlink_handle, parent_device.index, parent_gateway_address.clone()).await?.unwrap();

    let mac_address = parent_device.mac
        .expect("Parent device should have a MAC address")
        .octets();

    let gateway_address : [u8; 4] = parent_gateway_address.try_into().unwrap();

    let link_local_address : [u8; 6] = link_local_address(&parent_arp).unwrap().try_into().unwrap();

    let ip_network = parent_device.ips
        .first()
        .expect("Parent device should have an ip settings");

    let ip_address : [u8; 4] = ip_network.ip().into_address().unwrap().octets();

    let netmask : [u8; 4] = ip_network.mask().into_address().unwrap().octets();

    let result = NetworkSettings {
        ip_address,
        netmask,
        mac_address,
        gateway_address,
        link_local_address
    };

    Ok(result)
}*/