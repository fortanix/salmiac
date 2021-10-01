use ipnetwork::IpNetwork;
use log::{
    debug,
    info
};
use nix::net::if_::if_nametoindex;
use pcap::{Active, Capture};
use rtnetlink::packet::{RouteMessage};
use tokio::io;
use tokio::io::{WriteHalf, ReadHalf};
use tokio_vsock::VsockStream as AsyncVsockStream;
use tokio_vsock::VsockListener as AsyncVsockListener;
use futures::{StreamExt};
use futures::stream::Fuse;

use crate::packet_capture::{open_packet_capture, open_async_packet_capture};
use shared::device::{NetworkSettings, SetupMessages};
use shared::netlink::{AddressMessageExt, LinkMessageExt, RouteMessageExt};
use shared::{netlink, DATA_SOCKET, PACKET_LOG_STEP, log_packet_processing};
use shared::VSOCK_PARENT_CID;
use shared::socket::{
    AsyncWriteLvStream,
    AsyncReadLvStream,
};
use shared::vec_to_ip4;

use std::convert::TryFrom;
use std::sync::mpsc;
use std::thread;
use std::net::IpAddr;
use std::sync::mpsc::TryRecvError;

pub async fn run(vsock_port: u32) -> Result<(), String> {
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

    communicate_certificate(&mut enclave_port).await?;

    let read_capture = open_async_packet_capture(&parent_device.name, mtu)?;
    let write_capture = open_packet_capture(parent_device)?;

    let (vsock_read, vsock_write) = io::split(enclave_data_port);

    let pcap_read_loop = tokio::spawn(read_from_device_async(read_capture, vsock_write));

    debug!("Started pcap read loop!");

    let pcap_write_loop = tokio::spawn(write_to_device_async(write_capture, vsock_read));

    debug!("Started pcap write loop!");

    match tokio::try_join!(pcap_read_loop, pcap_write_loop) {
        Ok((read_returned, write_returned)) => {
            read_returned.map_err(|err| format!("Failure in pcap read loop: {:?}", err))?;
            write_returned.map_err(|err| format!("Failure in pcap write loop: {:?}", err))
        }
        Err(err) => {
            Err(format!("{:?}", err))
        }
    }
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

async fn communicate_certificate(vsock : &mut AsyncVsockStream) -> Result<(), String> {
    let msg : SetupMessages = vsock.read_lv().await?;

    let csr = match msg {
        SetupMessages::CSR(csr) => {
            csr
        }
        x => {
            return Err(format!("Expected message of type SetupMessages::CSR, but got {:?}", x))
        }
    };

    debug!("Received CSR {} from enclave!", csr);

    let certificate = em_app::request_issue_certificate("localhost", csr)
        .map_err(|err| format!("Failed to receive certificate {:?}", err))
        .and_then(|e| e.certificate.ok_or("No certificate returned".to_string()))?;

    debug!("Received certificate {}!", certificate);

    vsock.write_lv(&SetupMessages::Certificate(certificate)).await
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

    let parent_link = netlink::get_link_for_device(&netlink_handle, parent_device_index)
        .await?
        .expect(&format!("Device {} must have a link!", parent_device.name));

    let mac_address = parent_link.address()
        .map(|e| <[u8; 6]>::try_from(&e[..]))
        .expect("Parent link should have an address!")
        .map_err(|err| format!("Cannot convert array slice {:?}", err))?;

    let mtu = parent_link.mtu().expect("Parent device should have an MTU!");

    let ip_network = get_ip_network(&netlink_handle, parent_device_index).await?;

    let gateway_address = IpAddr::V4(vec_to_ip4(parent_gateway_address)?);

    let result = NetworkSettings {
        self_l2_address: mac_address,
        self_l3_address: ip_network,
        gateway_l3_address: gateway_address,
        mtu
    };

    Ok(result)
}

async fn get_gateway(netlink_handle : &rtnetlink::Handle, device_index : u32) -> Result<RouteMessage, String> {
    netlink::get_default_route_for_device(&netlink_handle, device_index)
        .await
        .and_then(|e| e.ok_or(format!("No default gateway was found in parent!")))
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

async fn read_from_device_async(mut capture: Fuse<pcap_async::PacketStream>, mut enclave_stream: WriteHalf<AsyncVsockStream>) -> Result<(), String> {
    let mut count = 0 as u32;

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

            enclave_stream.write_lv_bytes(packet.data()).await?;

            count = log_packet_processing(count, PACKET_LOG_STEP, "parent pcap");
        }
    }
}

async fn write_to_device_async(mut capture: Capture<Active>, mut from_enclave: ReadHalf<AsyncVsockStream>) -> Result<(), String> {
    let mut count = 0 as u32;
    let (packet_tx, packet_rx) = mpsc::channel();
    let (error_tx, error_rx) = mpsc::sync_channel(1);

    thread::spawn(move || {
        while let Ok(packet) = packet_rx.recv() {
            if let Err(e) = capture.sendpacket(packet) {
                let err = format!("Failed to write to pcap {:?}", e);

                error_tx.send(err).expect("Failed sending error");

                break;
            }
        }
    });

    loop {
        let packet = from_enclave.read_lv_bytes()
            .await
            .map_err(|err| format!("Failed to read packet from enclave {:?}", err))?;

        match error_rx.try_recv() {
            Err(TryRecvError::Disconnected) => {
                return Err(format!("pcap writer thread died prematurely"));
            }
            Ok(e) => {
                return Err(e)
            }
            _ => {}
        }

        packet_tx.send(packet)
            .map_err(|err| format!("Failed to send packet to pcap writer thread {:?}", err))?;

        count = log_packet_processing(count, PACKET_LOG_STEP, "parent vsock");
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
