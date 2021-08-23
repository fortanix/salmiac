use crate::net::device::{NetworkSettings, SetupMessages, get_default_network_device, RichNetworkInterface};
use crate::net::socket::{RichSocket, accept_vsock};
use crate::net::{netlink, vec_to_ip4};
use crate::net::packet_capture::{open_packet_capture, open_packet_capture_with_port_filter};
use crate::mode::VSOCK_PARENT_CID;

use rtnetlink::packet::{RouteMessage, NeighbourMessage};
use log::{
    debug,
    info,
    error
};
use vsock::{VsockStream, VsockListener};
use threadpool::ThreadPool;
use pcap::{Capture, Active};
use nix::sys::socket::SockAddr;

use std::convert::TryFrom;

pub fn run(vsock_port: u32, remote_port : Option<u32>) -> Result<(), String> {
    let thread_pool = ThreadPool::new(2);
    let mut enclave_listener = listen_parent(vsock_port)?;

    info!("Awaiting confirmation from enclave!");

    let mut enclave_port = accept_vsock(&mut enclave_listener)?;

    info!("Connected to enclave!");

    let parent_device = communicate_network_settings(&mut enclave_port)?;

    // `capture` should be properly locked when shared among threads (like tap device),
    // however copying captures is good enough for prototype and it just works.
    let (mut capture, mut write_capture) = if let Some(remote_port) = remote_port{
        (open_packet_capture_with_port_filter(&parent_device, remote_port)?,
        open_packet_capture_with_port_filter(&parent_device, remote_port)?)
    }
    else {
        (open_packet_capture(&parent_device)?,
        open_packet_capture(&parent_device)?)
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

fn communicate_network_settings(vsock : &mut VsockStream) -> Result<RichNetworkInterface, String> {
    let parent_device = get_default_network_device()
        .expect("Parent has no suitable network devices!");

    let network_settings = get_network_settings(&parent_device)?;

    debug!("Read network settings from parent {:?}", network_settings);

    vsock.send(SetupMessages::Settings(network_settings))?;

    debug!("Sent network settings to the enclave!");

    let msg : SetupMessages = vsock.receive()?;

    match msg {
        SetupMessages::SetupSuccessful => {
            info!("Enclave has setup networking!");
            Ok(parent_device)
        }
        x => {
            Err(format!("Expected message of type {:?}, but got {:?}", SetupMessages::SetupSuccessful, x))
        }
    }
}

#[tokio::main]
async fn get_network_settings(parent_device : &RichNetworkInterface) -> Result<NetworkSettings, String> {
    let (_netlink_connection, netlink_handle) = netlink::connect();
    tokio::spawn(_netlink_connection);

    debug!("Connected to netlink");

    let parent_gateway = netlink::RichRouteMessage(get_parent_gateway(
        &netlink_handle,
        parent_device.0.index).await?);

    let parent_gateway_address = parent_gateway.raw_gateway()
        .expect("No default gateway was found in parent!");

    let parent_arp = netlink::RichNeighbourMessage(get_parent_neighbour(
        &netlink_handle,
        parent_device.0.index,
        parent_gateway_address.clone()).await?);

    let mac_address = parent_device.0.mac
        .expect("Parent device has no MAC address!")
        .octets();

    let link_local_address = parent_arp.link_local_address()
        .map(|e|  <[u8; 6]>::try_from(&e[..]))
        .expect("ARP entry should have link local address")
        .map_err(|err| format!("Cannot convert vec {:?}", err))?;

    if parent_device.0.ips.len() > 1 {
        return Err(format!("Parent device {} should have only one ip address!", parent_device.0.name))
    }

    let ip_network = parent_device.0.ips[0];

    let gateway_address = vec_to_ip4(&parent_gateway_address)?;

    let mtu = parent_device.get_mtu()?;

    let result = NetworkSettings {
        self_l3_address: ip_network.ip(),
        self_prefix: ip_network.mask(),
        self_l2_address: mac_address,
        gateway_l2_address: gateway_address,
        gateway_l3_address: link_local_address,
        mtu
    };

    Ok(result)
}

async fn get_parent_gateway(netlink_handle : &rtnetlink::Handle, device_index : u32) -> Result<RouteMessage, String> {
    netlink::get_route_for_device(&netlink_handle, device_index)
        .await
        .and_then(|e| e.ok_or(format!("No default gateway was found in parent!")))
}

async fn get_parent_neighbour(netlink_handle : &rtnetlink::Handle, device_index : u32, gateway_address : Vec<u8>) -> Result<NeighbourMessage, String> {
    netlink::get_neighbour_for_device(netlink_handle, device_index, gateway_address.clone())
        .await
        .and_then(|e| e.ok_or(format!("No ARP entry found for address {:?} in parent!", gateway_address)))
}

fn read_from_device(capture: &mut Capture<Active>, enclave_stream: &mut VsockStream) -> Result<(), String> {
    let packet = capture.next().map_err(|err| format!("Failed to read packet from pcap {:?}", err))?;

    debug!("Captured packet from network device in parent! {:?}", packet);

    enclave_stream.send(packet.data.to_vec())?;

    debug!("Sent network packet to enclave!");

    Ok(())
}

fn write_to_device(capture: &mut Capture<Active>, from_enclave: &mut VsockStream) -> Result<(), String> {
    let packet : Vec<u8> = from_enclave.receive().map_err(|err| format!("Failed to read packet from enclave {:?}", err))?;

    debug!("Received packet from enclave! {:?}", packet);

    capture.sendpacket(packet).map_err(|err| format!("Failed to send packet to device {:?}", err))?;

    debug!("Sent raw packet to network device!");

    Ok(())
}

fn listen_parent(port : u32) -> Result<VsockListener, String> {
    let sockaddr = SockAddr::new_vsock(VSOCK_PARENT_CID, port);

    VsockListener::bind(&sockaddr).map_err(|_| format!("Could not bind to {:?}", sockaddr))
}