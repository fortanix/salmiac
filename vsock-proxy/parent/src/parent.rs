use ipnetwork::IpNetwork;
use log::{
    debug,
    info
};
use nix::net::if_::if_nametoindex;
use pcap::{Active, Capture};
use rtnetlink::packet::{NeighbourMessage, RouteMessage};
use tokio::io;
use tokio::io::{WriteHalf, ReadHalf};
use tokio_vsock::VsockStream as AsyncVsockStream;
use tokio_vsock::VsockListener as AsyncVsockListener;
use futures::{StreamExt};
use futures::stream::Fuse;

use crate::packet_capture::{open_packet_capture, open_packet_capture_with_port_filter, open_async_packet_capture, open_async_packet_capture_with_port_filter};
use shared::device::{NetworkSettings, SetupMessages};
use shared::netlink::{AddressMessageExt, LinkMessageExt, NeighbourMessageExt, RouteMessageExt};
use shared::{netlink, DATA_SOCKET};
use shared::VSOCK_PARENT_CID;
use shared::socket::{
    AsyncWriteLvStream,
    AsyncReadLvStream,
};
use shared::vec_to_ip4;

use std::convert::TryFrom;
use std::net::IpAddr;

pub async fn run(vsock_port: u32, remote_port : Option<u32>) -> Result<(), String> {
    info!("Awaiting confirmation from enclave!");

    let mut enclave_listener = listen_to_parent(vsock_port)?;
    let mut data_listener = listen_to_parent(DATA_SOCKET)?;

    let (enclave_port_result, enclave_data_port_result) = tokio::join!(
        accept(&mut enclave_listener),
        accept(&mut data_listener));

    let mut enclave_port = enclave_port_result?;
    let enclave_data_port = enclave_data_port_result?;

    info!("Connected to enclave!");

    let parent_device = pcap::Device::lookup()
        .map_err(|err| format!("Cannot find device for packet capture {:?}", err))?;

    let network_settings = get_network_settings(&parent_device).await?;

    let mtu = network_settings.mtu;
    communicate_network_settings(network_settings, &mut enclave_port).await?;

    let (mut read_capture, mut write_capture) = if let Some(remote_port) = remote_port {
        let read_capture = open_async_packet_capture_with_port_filter(
            &parent_device.name,
            mtu,
            remote_port)?;
        let write_capture = open_packet_capture_with_port_filter(parent_device, remote_port)?;

        (read_capture, write_capture)
    } else {
        let read_capture = open_async_packet_capture(&parent_device.name, mtu)?;
        let write_capture = open_packet_capture(parent_device)?;

        (read_capture, write_capture)
    };

    let (mut vsock_read, mut vsock_write) = io::split(enclave_data_port);

    let pcap_read_loop = tokio::spawn(async move {
        read_from_device_async(&mut read_capture, &mut vsock_write).await
    });

    debug!("Started pcap read loop!");

    let pcap_write_loop = tokio::spawn(async move {
        write_to_device_async(&mut write_capture, &mut vsock_read).await
    });

    debug!("Started pcap write loop!");

    let (read_returned, write_returned) = tokio::join!(pcap_read_loop, pcap_write_loop);

    read_returned.map_err(|err| format!("Failure in pcap read loop: {:?}", err))??;
    write_returned.map_err(|err| format!("Failure in pcap write loop: {:?}", err))??;

    Ok(())
}

async fn communicate_network_settings(settings : NetworkSettings, vsock : &mut AsyncVsockStream) -> Result<(), String> {
    debug!("Read network settings from parent {:?}", settings);

    vsock.write_lv(&SetupMessages::Settings(settings)).await?;

    debug!("Sent network settings to the enclave!");

    let msg : SetupMessages = vsock.read_lv().await?;

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
    loop {
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
            debug!("Captured packet from pcap! {:?}", packet);

            enclave_stream.write_lv_bytes(packet.data()).await?;

            debug!("Sent network packet to enclave!");
        }
    }
}

async fn write_to_device_async(capture: &mut Capture<Active>, from_enclave: &mut ReadHalf<AsyncVsockStream>) -> Result<(), String> {
    loop {
        let packet = from_enclave.read_lv_bytes()
            .await
            .map_err(|err| format!("Failed to read packet from enclave {:?}", err))?;

        debug!("Received packet from enclave! {:?}", packet);

        capture.sendpacket(packet).map_err(|err| format!("Failed to send packet to device {:?}", err))?;

        debug!("Sent packet to network device!");
    }
}

fn listen_to_parent(port : u32) -> Result<AsyncVsockListener, String> {
    AsyncVsockListener::bind(VSOCK_PARENT_CID, port)
        .map_err(|_| format!("Could not bind to cid: {}, port: {}", VSOCK_PARENT_CID, port))
}

async fn accept(listener: &mut AsyncVsockListener) -> Result<AsyncVsockStream, String> {
    listener.accept()
        .await
        .map(|r| r.0)
        .map_err(|err| format!("Accept from vsock failed: {:?}", err))
}
