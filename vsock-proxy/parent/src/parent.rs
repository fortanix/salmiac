use ipnetwork::IpNetwork;
use log::{
    debug,
    error,
    info
};
use nix::net::if_::if_nametoindex;
use nix::sys::socket::SockAddr;
use pcap::{Active, Capture};
use rtnetlink::packet::{NeighbourMessage, RouteMessage};
use threadpool::ThreadPool;
use vsock::{VsockListener, VsockStream};

use crate::packet_capture::{open_packet_capture, open_packet_capture_with_port_filter};
use shared::device::{NetworkSettings, SetupMessages};
use shared::netlink::{AddressMessageExt, LinkMessageExt, NeighbourMessageExt, RouteMessageExt};
use shared::netlink;
use shared::VSOCK_PARENT_CID;
use shared::socket::LvStream;
use shared::vec_to_ip4;

use std::convert::TryFrom;
use std::net::IpAddr;


pub fn run(vsock_port: u32, remote_port : Option<u32>) -> Result<(), String> {
    let thread_pool = ThreadPool::new(2);
    let enclave_listener = listen_parent(vsock_port)?;

    info!("Awaiting confirmation from enclave!");

    let mut enclave_port = enclave_listener.accept()
        .map(|r| r.0)
        .map_err(|err| format!("Accept from vsock failed: {:?}", err))?;

    info!("Connected to enclave!");

    let parent_device = pcap::Device::lookup()
        .map_err(|err| format!("Cannot find device for packet capture {:?}", err))?;

    let network_settings = get_network_settings(&parent_device)?;

    let mtu = network_settings.mtu;
    communicate_network_settings(network_settings, &mut enclave_port)?;

    // `capture` should be properly locked when shared among threads (like tap device),
    // however copying captures is good enough for prototype and it just works.
    let (mut capture, mut write_capture) = if let Some(remote_port) = remote_port{
        (open_packet_capture_with_port_filter(parent_device.clone(), remote_port, mtu)?,
         open_packet_capture_with_port_filter(parent_device, remote_port, mtu)?)
    }
    else {
        (open_packet_capture(parent_device.clone(), mtu)?,
         open_packet_capture(parent_device, mtu)?)
    };

    debug!("Listening to packets from network device!");

    let mut vsock_write = enclave_port.clone();
    let mut vsock_read = enclave_port.clone();

    thread_pool.execute(move || {
        loop {
            match read_from_device(&mut capture, &mut vsock_write) {
                Err(e) => {
                    error!("Failure reading from network device {:?}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    thread_pool.execute(move || {
        loop {
            match write_to_device(&mut write_capture, &mut vsock_read) {
                Err(e) => {
                    error!("Failure writing to network device {:?}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    thread_pool.join();

    Ok(())
}

fn communicate_network_settings(settings : NetworkSettings, vsock : &mut VsockStream) -> Result<(), String> {
    debug!("Read network settings from parent {:?}", settings);

    vsock.write_lv(&SetupMessages::Settings(settings))?;

    debug!("Sent network settings to the enclave!");

    let msg : SetupMessages = vsock.read_lv()?;

    match msg {
        SetupMessages::SetupSuccessful => {
            info!("Enclave has setup networking!");
            Ok(())
        }
        x => {
            Err(format!("Expected message of type {:?}, but got {:?}", SetupMessages::SetupSuccessful, x))
        }
    }
}

#[tokio::main]
async fn get_network_settings(parent_device : &pcap::Device) -> Result<NetworkSettings, String> {
    let (_netlink_connection, netlink_handle) = netlink::connect();
    tokio::spawn(_netlink_connection);

    debug!("Connected to netlink");

    let parent_device_index = if_nametoindex(parent_device.name.as_str())
        .map_err(|err| format!("Cannot find index for device {}, error {:?}", parent_device.name, err))?;

    let parent_gateway = get_gateway(&netlink_handle, parent_device_index).await?;

    let parent_gateway_address = parent_gateway.raw_gateway()
        .expect("No default gateway was found in parent!");

    let parent_arp = get_neighbor_by_address(
        &netlink_handle,
        parent_device_index,
        parent_gateway_address).await?;

    let parent_link = netlink::get_link_for_device(&netlink_handle, parent_device_index)
        .await?
        .expect(&format!("Device {} must have a link!", parent_device.name));

    let mac_address = parent_link.address()
        .map(|e| <[u8; 6]>::try_from(&e[..]))
        .expect("Parent link should have an address!")
        .map_err(|err| format!("Cannot convert array slice {:?}", err))?;

    let mtu = parent_link.mtu().expect("Parent device should have an MTU!");

    let link_local_address = parent_arp.link_local_address()
        .map(|e|  <[u8; 6]>::try_from(&e[..]))
        .expect("ARP entry should have link local address")
        .map_err(|err| format!("Cannot convert array slice {:?}", err))?;

    let ip_network = get_ip_network(&netlink_handle, parent_device_index).await?;

    let gateway_address = IpAddr::V4(vec_to_ip4(parent_gateway_address)?);

    let result = NetworkSettings {
        self_l2_address: mac_address,
        self_l3_address: ip_network,
        gateway_l2_address: gateway_address,
        gateway_l3_address: link_local_address,
        mtu
    };

    Ok(result)
}

async fn get_gateway(netlink_handle : &rtnetlink::Handle, device_index : u32) -> Result<RouteMessage, String> {
    netlink::get_default_route_for_device(&netlink_handle, device_index)
        .await
        .and_then(|e| e.ok_or(format!("No default gateway was found in parent!")))
}

async fn get_neighbor_by_address(netlink_handle : &rtnetlink::Handle, device_index : u32, l3_address: &[u8]) -> Result<NeighbourMessage, String> {
    netlink::get_neighbour_for_device(netlink_handle, device_index, l3_address.clone())
        .await
        .and_then(|e| e.ok_or(format!("No ARP entry found for address {:?} in parent!", l3_address)))
}

async fn get_ip_network(netlink_handle : &rtnetlink::Handle, device_index : u32) -> Result<IpNetwork, String> {
    let addresses = netlink::get_inet_addresses_for_device(netlink_handle, device_index).await?;

    if addresses.len() != 1 {
        Err(format!("Device with index {} should have only one inet address", device_index))
    }
    else {
        addresses[0].ip_network()
    }
}

fn read_from_device(capture: &mut Capture<Active>, enclave_stream: &mut VsockStream) -> Result<(), String> {
    let packet = capture.next().map_err(|err| format!("Failed to read packet from pcap {:?}", err))?;

    debug!("Captured packet from network device in parent! {:?}", packet);

    enclave_stream.write_lv_bytes(&packet.data)?;

    debug!("Sent network packet to enclave!");

    Ok(())
}

fn write_to_device(capture: &mut Capture<Active>, from_enclave: &mut VsockStream) -> Result<(), String> {
    let packet = from_enclave.read_lv_bytes().map_err(|err| format!("Failed to read packet from enclave {:?}", err))?;

    debug!("Received packet from enclave! {:?}", packet);

    capture.sendpacket(packet).map_err(|err| format!("Failed to send packet to device {:?}", err))?;

    debug!("Sent raw packet to network device!");

    Ok(())
}

fn listen_parent(port : u32) -> Result<VsockListener, String> {
    let sockaddr = SockAddr::new_vsock(VSOCK_PARENT_CID, port);

    VsockListener::bind(&sockaddr).map_err(|_| format!("Could not bind to {:?}", sockaddr))
}
