use ipnetwork::IpNetwork;
use log::{
    debug,
    info
};
use nix::net::if_::if_nametoindex;
use nix::sys::socket::SockAddr;
use pcap::{Active, Capture};
use rtnetlink::packet::{NeighbourMessage, RouteMessage};
use vsock::{VsockListener, VsockStream};
use tokio::io;
use tokio_vsock::VsockStream as AsyncVsockStream;
use tokio_vsock::VsockListener as AsyncVsockListener;

use crate::packet_capture::{open_packet_capture, open_packet_capture_with_port_filter, open_async_packet_capture, open_async_packet_capture_with_port_filter};
use shared::device::{NetworkSettings, SetupMessages};
use shared::netlink::{AddressMessageExt, LinkMessageExt, NeighbourMessageExt, RouteMessageExt};
use shared::netlink;
use shared::VSOCK_PARENT_CID;
use shared::socket::{
    AsyncWriteLvStream,
    AsyncReadLvStream,
    LvStream
};
use shared::vec_to_ip4;

use std::convert::TryFrom;
use std::net::IpAddr;
use tokio::io::{WriteHalf, ReadHalf};
use futures::{StreamExt};
use futures::stream::Fuse;

pub async fn run(vsock_port: u32, remote_port : Option<u32>) -> Result<(), String> {
    let enclave_listener = listen_parent(vsock_port)?;

    info!("Awaiting confirmation from enclave!");

    let mut enclave_port = enclave_listener.accept()
        .map(|r| r.0)
        .map_err(|err| format!("Accept from vsock failed: {:?}", err))?;

    info!("Connected to enclave!");

    info!("Awaiting confirmation from enclave for data!");

    let mut data_listener = listen_parent_async(100)?;
    let enclave_data_port = data_listener.accept()
        .await
        .map(|r| r.0)
        .map_err(|err| format!("Accept from vsock failed: {:?}", err))?;

    info!("Connected to enclave for data!");

    let parent_device = pcap::Device::lookup()
        .map_err(|err| format!("Cannot find device for packet capture {:?}", err))?;

    let network_settings = get_network_settings(&parent_device).await?;

    let mtu = network_settings.mtu;
    communicate_network_settings(network_settings, &mut enclave_port)?;

    let (mut read_capture, mut write_capture) = if let Some(remote_port) = remote_port {
        let read_capture = open_async_packet_capture_with_port_filter(
            &parent_device.name,
            mtu,
            remote_port)?;
        let write_capture = open_packet_capture_with_port_filter(parent_device, remote_port)?;

        (read_capture.fuse(), write_capture)
    } else {
        let read_capture = open_async_packet_capture(&parent_device.name, mtu)?;
        let write_capture = open_packet_capture(parent_device)?;

        (read_capture.fuse(), write_capture)
    };

    let (mut vsock_read, mut vsock_write) = io::split(enclave_data_port);

    let pcap_read_loop = tokio::spawn(async move {
        loop {
            match read_from_device_async(&mut read_capture, &mut vsock_write).await {
                Err(e) => {
                    return Err(e)
                }
                _ => {}
            }
        }
    });

    debug!("Started pcap read loop!");

    let pcap_write_loop = tokio::spawn(async move {
        loop {
            match write_to_device_async(&mut write_capture, &mut vsock_read).await {
                Err(e) => {
                    return Err(e)
                }
                _ => {}
            }
        }
    });

    debug!("Started pcap write loop!");

    let (r, l) = tokio::join!(pcap_read_loop, pcap_write_loop);

    r.map_err(|err| format!("Failure in pcap read loop: {:?}", err))??;
    l.map_err(|err| format!("Failure in pcap write loop: {:?}", err))??;

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

async fn read_from_device_async(capture: &mut Fuse<pcap_async::PacketStream>, enclave_stream: &mut WriteHalf<AsyncVsockStream>) -> Result<(), String> {
    let packets = match capture.next().await {
        Some(Ok(packet)) => {
            packet
        }
        Some(Err(e)) => {
            return Err(format!("Failed to read packet from pcap {:?}", e))
        }
        None => {
            return Ok(())
        }
    };

    for packet in packets {
        debug!("Captured packet from network device in parent! {:?}", packet);

        enclave_stream.write_lv_bytes_async(packet.data()).await?;

        debug!("Sent network packet to enclave!");
    }

    Ok(())
}

async fn write_to_device_async(capture: &mut Capture<Active>, from_enclave: &mut ReadHalf<AsyncVsockStream>) -> Result<(), String> {
    let packet = from_enclave.read_lv_bytes_async()
        .await
        .map_err(|err| format!("Failed to read packet from enclave {:?}", err))?;

    debug!("Received packet from enclave! {:?}", packet);

    capture.sendpacket(packet).map_err(|err| format!("Failed to send packet to device {:?}", err))?;

    debug!("Sent raw packet to network device!");

    Ok(())
}

#[cfg(feature = "sync")]
fn read_from_device(capture: &mut Capture<Active>, enclave_stream: &mut VsockStream) -> Result<(), String> {
    let packet = capture.next().map_err(|err| format!("Failed to read packet from pcap {:?}", err))?;

    debug!("Captured packet from network device in parent! {:?}", packet);

    enclave_stream.write_lv_bytes(&packet.data)?;

    debug!("Sent network packet to enclave!");

    Ok(())
}

#[cfg(feature = "sync")]
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

fn listen_parent_async(port : u32) -> Result<AsyncVsockListener, String> {
    AsyncVsockListener::bind(VSOCK_PARENT_CID, port)
        .map_err(|_| format!("Could not bind to cid: {}, port: {}", VSOCK_PARENT_CID, port))
}
