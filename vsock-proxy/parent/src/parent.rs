use etherparse::SlicedPacket;
use etherparse::InternetSlice::Ipv4;
use etherparse::TransportSlice::Tcp;
use ipnetwork::IpNetwork;
use log::{
    debug,
    info,
    warn
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
use std::net::{IpAddr};
use std::sync::mpsc::TryRecvError;
use std::env;
use std::fs;

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

    let user_program = tokio::spawn(await_user_program_return(enclave_port));

    tokio::select! {
        result = pcap_read_loop => {
            handle_background_task_exit(result, "pcap read loop")
        },
        result = pcap_write_loop => {
            handle_background_task_exit(result, "pcap write loop")
        },
        result = user_program => {
            result.map_err(|err| format!("Join error in user program wait loop. {:?}", err))?
        },
    }
}

async fn await_user_program_return(mut vsock : AsyncVsockStream) -> Result<UserProgramExitStatus, String> {
    let msg : SetupMessages = vsock.read_lv().await?;

    extract_enum_value!(msg, SetupMessages::UserProgramExit(status) => status)
}

async fn communicate_enclave_settings(network_settings : NetworkSettings, vsock : &mut AsyncVsockStream) -> Result<(), String> {
    communicate_network_settings(network_settings, vsock).await?;

    communicate_certificates(vsock).await?;

    Ok(())
}

async fn communicate_network_settings(settings : NetworkSettings, vsock : &mut AsyncVsockStream) -> Result<(), String> {
    debug!("Read network settings from parent {:?}", settings);

    vsock.write_lv(&SetupMessages::Settings(settings)).await?;

    debug!("Sent network settings to the enclave!");

    Ok(())
}

async fn communicate_certificates(vsock : &mut AsyncVsockStream) -> Result<(), String> {
    let app_config_id = get_app_config_id();

    vsock.write_lv(&SetupMessages::ApplicationConfigId(app_config_id)).await?;

    // Don't bother looking for a node agent address unless there's at least one certificate configured. This allows us to run
    // with the NODE_AGENT environment variable being unset, if there are no configured certificates.
    let mut node_agent_address : Option<String> = None;

    // Process certificate requests until we get the SetupSuccessful message indicating that the enclave is done with
    // setup. There can be any number of certificate requests, including 0.
    loop {
        let msg: SetupMessages = vsock.read_lv().await?;

        match msg {
            SetupMessages::SetupSuccessful => return Ok(()),
            SetupMessages::CSR(csr) => {
                let addr = match node_agent_address {
                    Some(ref addr) => addr.clone(),
                    None => {
                        let result = env::var("NODE_AGENT").map_err(|err| format!("Failed to read NODE_AGENT var. {:?}", err))?;

                        let addr = if !result.starts_with("http://") {
                           "http://".to_string() + &result
                        } else {
                            result
                        };
                        node_agent_address = Some(addr.clone());
                        addr
                    },
                };
                let certificate = em_app::request_issue_certificate(&addr, csr)
                .map_err(|err| format!("Failed to receive certificate {:?}", err))
                .and_then(|e| e.certificate.ok_or("No certificate returned".to_string()))?;

                vsock.write_lv(&SetupMessages::Certificate(certificate)).await?;
            },
            other => return Err(format!("While processing certificate requests, expected SetupMessages::CSR(csr) or SetupMessages:SetupSuccessful, but got {:?}",
                                        other)),
        };
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

    let dns_file = fs::read_to_string("/etc/resolv.conf")
        .map_err(|err| format!("Failed reading parent's /etc/resolv.conf. {:?}", err))?;

    let result = NetworkSettings {
        self_l2_address: mac_address,
        self_l3_address: ip_network,
        gateway_l3_address: gateway_address,
        mtu,
        dns_file : dns_file.into_bytes()
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

            let mut data = packet.into_data();

            recompute_packet_checksum(&mut data)?;

            enclave_stream.write_lv_bytes(&data).await?;

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

fn get_app_config_id() -> Option<String> {
    match env::var("ENCLAVEOS_APPCONFIG_ID").or(env::var("APPCONFIG_ID")) {
        Ok(result) => {
            Some(result)
        }
        Err(err) => {
            warn!("Failed reading env var ENCLAVEOS_APPCONFIG_ID or APPCONFIG_ID, assuming var is not set. {:?}", err);
            None
        }
    }
}

fn recompute_packet_checksum(data : &mut[u8]) -> Result<(), String> {
    let ethernet_packet = SlicedPacket::from_ethernet(&data)
        .map_err(|err| format!("Cannot parse ethernet packet. {:?}", err))?;

    let checksum_result = match (ethernet_packet.ip, ethernet_packet.transport) {
        (Some(Ipv4(ip_packet, _)), Some(Tcp(tcp_packet))) => {
            let checksum = tcp_packet.calc_checksum_ipv4(&ip_packet, ethernet_packet.payload)
                .map_err(|err| format!("Failed calculating checksum. {:?}", err))?;

            // SAFETY:
            // Both the starting and other pointer are in bounds of the same allocated object (`data`).
            // Both pointers are derived from a pointer to the same object (`data`).
            // The distance between the pointers, in bytes, is be an exact multiple of the size of u8 (trivial, as the size is 1).
            // The distance between the pointers, in bytes, doesn't overflow an isize (packet size is less than isize::max_value()).
            // The distance doesn't wrap around “wrapping around” the address space.
            let offset = unsafe {
                tcp_packet.slice()[16..]
                    .as_ptr()
                    .offset_from(data.as_ptr())
                    as usize
            };

            debug!("Computed new checksum for tcp packet. \
             Source {:?}, destination {:?}, payload len {}, old checksum {}, new checksum {}",
                   ip_packet.source_addr(),
                   ip_packet.destination_addr(),
                   ethernet_packet.payload.len(),
                   tcp_packet.checksum(),
                   checksum);

            Some((offset, checksum))
        }
        _ => None
    };

    if let Some((checksum_offset, checksum)) = checksum_result {
        let checksum_slice = &mut data[checksum_offset..=(checksum_offset+2)];
        let checksum_bytes = checksum.to_be_bytes();

        checksum_slice[0] = checksum_bytes[0];
        checksum_slice[1] = checksum_bytes[1];
    }

    Ok(())
}