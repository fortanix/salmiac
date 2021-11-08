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
use shared::{extract_enum_value, handle_background_task_exit, UserProgramExitStatus};
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
use std::env;

pub async fn run(vsock_port: u32) -> Result<UserProgramExitStatus, String> {
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
    communicate_enclave_settings(network_settings, &mut enclave_port).await?;

    let read_capture = open_async_packet_capture(&parent_device.name, mtu)?;
    let write_capture = open_packet_capture(parent_device)?;

    let (vsock_read, vsock_write) = io::split(enclave_data_port);

    let pcap_read_loop = tokio::spawn(read_from_device_async(read_capture, vsock_write));

    debug!("Started pcap read loop!");

    let pcap_write_loop = tokio::spawn(write_to_device_async(write_capture, vsock_read));

    debug!("Started pcap write loop!");

    let client_program = tokio::spawn(await_client_program_return(enclave_port));

    tokio::select! {
        result = pcap_read_loop => {
            handle_background_task_exit(result, "pcap read loop")
        },
        result = pcap_write_loop => {
            handle_background_task_exit(result, "pcap write loop")
        },
        result = client_program => {
            result.map_err(|err| format!("Join error in client program wait loop. {:?}", err))?
        },
    }
}

async fn await_client_program_return(mut vsock : AsyncVsockStream) -> Result<UserProgramExitStatus, String> {
    let msg : SetupMessages = vsock.read_lv().await?;

    extract_enum_value!(msg, SetupMessages::UserProgramExit(status) => status)
}

async fn communicate_enclave_settings(network_settings : NetworkSettings, vsock : &mut AsyncVsockStream) -> Result<(), String> {
    communicate_network_settings(network_settings, vsock).await?;

    communicate_certificate(vsock).await?;

    let msg : SetupMessages = vsock.read_lv().await?;

    extract_enum_value!(msg, SetupMessages::SetupSuccessful => ())
}

async fn communicate_network_settings(settings : NetworkSettings, vsock : &mut AsyncVsockStream) -> Result<(), String> {
    debug!("Read network settings from parent {:?}", settings);

    vsock.write_lv(&SetupMessages::Settings(settings)).await?;

    debug!("Sent network settings to the enclave!");

    Ok(())
}

async fn communicate_certificate(vsock : &mut AsyncVsockStream) -> Result<(), String> {
    let csr_msg: SetupMessages = vsock.read_lv().await?;

    let csr = extract_enum_value!(csr_msg, SetupMessages::CSR(csr) => csr)?;

    let node_agent_address = {
        let result = env::var("NODE_AGENT")
            .map_err(|err| format!("Failed to read NODE_AGENT var. {:?}", err))?;

        if !result.starts_with("http://") {
            "http://".to_string() + &result
        } else {
            result
        }
    };

    let certificate = em_app::request_issue_certificate(&node_agent_address, csr)
        .map_err(|err| format!("Failed to receive certificate {:?}", err))
        .and_then(|e| e.certificate.ok_or("No certificate returned".to_string()))?;

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
