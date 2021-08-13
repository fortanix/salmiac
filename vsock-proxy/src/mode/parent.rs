use crate::net::device::{NetworkSettings, SetupMessages, get_default_network_device};
use crate::net::socket::{RichSocket, accept_vsock};
use crate::net::{netlink, vec_to_ip, vec_to_mac};
use crate::net::packet_capture::open_packet_capture;
use crate::mode::VSOCK_PARENT_CID;

use pnet_datalink::{NetworkInterface};
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

pub fn run(vsock_port: u32, remote_port : u32, thread_pool : ThreadPool) -> Result<(), String> {
    let mut enclave_listener = listen_parent(vsock_port)?;

    info!("Awaiting confirmation from enclave!");

    let mut enclave_port = accept_vsock(&mut enclave_listener)?;

    info!("Connected to enclave!");

    let parent_device = communicate_network_settings(&mut enclave_port)?;

    // `capture` should be properly locked when shared among threads (like tap device),
    // however copying captures is good enough for prototype and it just works.
    let mut capture = open_packet_capture(remote_port, &parent_device.name)?;
    let mut write_capture = open_packet_capture(remote_port, &parent_device.name)?;

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

fn communicate_network_settings(vsock : &mut VsockStream) -> Result<NetworkInterface, String> {
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
async fn get_network_settings(parent_device : &NetworkInterface) -> Result<NetworkSettings, String> {
    let (_netlink_connection, netlink_handle) = netlink::connect();
    tokio::spawn(_netlink_connection);

    debug!("Connected to netlink");

    let parent_gateway = netlink::RichRouteMessage(get_parent_gateway(
        &netlink_handle,
        parent_device.index).await?);

    let parent_gateway_address = parent_gateway.raw_gateway()
        .expect("No default gateway was found in parent!");

    let parent_arp = netlink::RichNeighbourMessage(get_parent_neighbour(
        &netlink_handle,
        parent_device.index,
        parent_gateway_address.clone()).await?);

    let mac_address = parent_device.mac
        .expect("Parent device has no MAC address!");

    let link_local_address = vec_to_mac(
        &parent_arp.link_local_address()
            .expect("ARP entry should have link local address"))?;

    let ip_network = parent_device.ips
        .first()
        .expect("Parent device has no ip settings!");

    let gateway_address = vec_to_ip(&parent_gateway_address)?;

    let result = NetworkSettings {
        ip_address  : ip_network.ip(),
        netmask     : ip_network.mask(),
        mac_address,
        gateway_address,
        link_local_address
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