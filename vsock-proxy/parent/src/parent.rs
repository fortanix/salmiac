use etherparse::InternetSlice::Ipv4;
use etherparse::SlicedPacket;
use etherparse::TransportSlice::{Tcp, Udp, Unknown};
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::Fuse;
use futures::StreamExt;
use ipnetwork::IpNetwork;
use log::{debug, info, warn};
use nix::net::if_::if_nametoindex;
use pcap::{Active, Capture, Device};
use rtnetlink::packet::NUD_PERMANENT;
use tokio::io;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tokio_vsock::VsockStream as AsyncVsockStream;
use tokio_vsock::{VsockListener as AsyncVsockListener, VsockStream};

use crate::packet_capture::{open_async_packet_capture, open_packet_capture};
use shared::device::{ApplicationConfiguration, CCMBackendUrl, GlobalNetworkSettings, NetworkDeviceSettings, SetupMessages};
use shared::netlink::{LinkMessageExt, Netlink, NetlinkCommon};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use shared::VSOCK_PARENT_CID;
use shared::{extract_enum_value, handle_background_task_exit, UserProgramExitStatus};
use shared::{log_packet_processing, PACKET_LOG_STEP};

use shared::netlink::arp::{ARPEntry, NetlinkARP};
use shared::netlink::route::{Gateway, NetlinkRoute, Route};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::env;
use std::fs;
use std::mem;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::TryRecvError;
use std::thread;

// Position of a checksum field in TCP header according to rfc 793.
const TCP_CHECKSUM_FIELD_INDEX: usize = 16;

const UDP_CHECKSUM_FIELD_INDEX: usize = 6;

const IPV4_CHECKSUM_FIELD_INDEX: usize = 10;

pub async fn run(vsock_port: u32) -> Result<UserProgramExitStatus, String> {
    info!("Awaiting confirmation from enclave.");

    let mut enclave_port = create_vsock_stream(vsock_port).await?;

    info!("Connected to enclave.");

    let devices = setup_parent(&mut enclave_port).await?;

    let mut background_tasks = FuturesUnordered::new();

    for e in devices {
        let res = start_pcap_loops(e.0, e.1)?;

        background_tasks.push(res.0);
        background_tasks.push(res.1);
    }

    let user_program = tokio::spawn(await_user_program_return(enclave_port));

    if !background_tasks.is_empty() {
        tokio::select! {
            result = background_tasks.next() => {
                handle_background_task_exit(result, "pcap loop")
            },
            result = user_program => {
                result.map_err(|err| format!("Join error in user program wait loop. {:?}", err))?
            },
        }
    } else {
        user_program.await.map_err(|err| format!("Join error in user program wait loop. {:?}", err))?
    }
}

async fn setup_parent(vsock: &mut AsyncVsockStream) -> Result<Vec<(Device, VsockStream)>, String> {
    send_application_configuration(vsock).await?;

    let devices = setup_network_devices(vsock).await?;

    send_global_network_settings(vsock).await?;

    communicate_certificates(vsock).await?;

    Ok(devices)
}

async fn setup_network_devices(enclave_port: &mut AsyncVsockStream) -> Result<Vec<(Device, VsockStream)>, String> {
    let netlink = Netlink::new();

    let devices = pcap::Device::list().map_err(|err| format!("Failed retrieving network device list. {:?}", err))?;

    let mut device_settings: Vec<NetworkDeviceSettings> = Vec::new();
    let mut device_listeners: Vec<AsyncVsockListener> = Vec::new();

    for device in &devices {
        let device_name = device.name.clone();

        if device_name != "lo" && device_name != "any" {
            match get_network_settings(device, &netlink).await {
                Ok(settings) => {
                    device_listeners.push(listen_to_parent(settings.index)?);
                    device_settings.push(settings);
                }
                Err(e) => {
                    warn!(
                        "Failed retrieving network settings for device {}, device won't be setup! {}",
                        device_name, e
                    )
                }
            };
        }
    }

    enclave_port
        .write_lv(&SetupMessages::NetworkDeviceSettings(device_settings))
        .await?;

    let mut device_streams: Vec<VsockStream> = Vec::new();

    for mut listener in device_listeners {
        device_streams.push(accept(&mut listener).await?);
    }

    let result = devices.into_iter().zip(device_streams.into_iter()).collect();

    Ok(result)
}

async fn send_global_network_settings(enclave_port: &mut AsyncVsockStream) -> Result<(), String> {
    let dns_file = fs::read_to_string("/etc/resolv.conf")
        .map_err(|err| format!("Failed reading parent's /etc/resolv.conf. {:?}", err))?
        .into_bytes();

    let network_settings = GlobalNetworkSettings { dns_file };

    enclave_port
        .write_lv(&SetupMessages::GlobalNetworkSettings(network_settings))
        .await?;

    debug!("Sent global network settings to the enclave.");

    Ok(())
}

fn start_pcap_loops(
    network_device: Device,
    vsock: AsyncVsockStream,
) -> Result<(JoinHandle<Result<(), String>>, JoinHandle<Result<(), String>>), String> {
    let read_capture = open_async_packet_capture(&network_device.name)?;
    let write_capture = open_packet_capture(network_device)?;

    let (vsock_read, vsock_write) = io::split(vsock);

    let pcap_read_loop = tokio::spawn(read_from_device_async(read_capture, vsock_write));

    let pcap_write_loop = tokio::spawn(write_to_device_async(write_capture, vsock_read));

    Ok((pcap_read_loop, pcap_write_loop))
}

async fn await_user_program_return(mut vsock: AsyncVsockStream) -> Result<UserProgramExitStatus, String> {
    extract_enum_value!(vsock.read_lv().await?, SetupMessages::UserProgramExit(status) => status)
}

async fn communicate_certificates(vsock: &mut AsyncVsockStream) -> Result<(), String> {
    // Don't bother looking for a node agent address unless there's at least one certificate configured. This allows us to run
    // with the NODE_AGENT environment variable being unset, if there are no configured certificates.
    let mut node_agent_address: Option<String> = None;

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
                        let result = env::var("NODE_AGENT")
                            .map_err(|err| format!("Failed to read NODE_AGENT var. {:?}", err))?;

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

async fn send_application_configuration(vsock: &mut AsyncVsockStream) -> Result<(), String> {
    let ccm_backend_url = env_var_or_none("CCM_BACKEND").map_or(Ok(CCMBackendUrl::default()), |e| CCMBackendUrl::new(&e))?;

    let id = get_app_config_id();

    let skip_server_verify = env_var_or_none("SKIP_SERVER_VERIFY")
        .map_or(Ok(false), |e| bool::from_str(&e))
        .map_err(|err| format!("Failed converting SKIP_SERVER_VERIFY env var to bool. {:?}", err))?;

    let application_configuration = ApplicationConfiguration {
        id,
        ccm_backend_url,
        skip_server_verify,
    };

    vsock
        .write_lv(&SetupMessages::ApplicationConfig(application_configuration))
        .await
}

async fn get_network_settings(device: &pcap::Device, netlink: &Netlink) -> Result<NetworkDeviceSettings, String> {
    let device_index = if_nametoindex(device.name.as_str())
        .map_err(|err| format!("Cannot find index for device {}, error {:?}", device.name, err))?;

    let device_link = netlink
        .get_link_for_device(device_index)
        .await?
        .expect(&format!("Device {} must have a link.", device.name));

    let mac_address = device_link
        .address()
        .map(|e| <[u8; 6]>::try_from(&e[..]))
        .expect("Parent link should have an address.")
        .map_err(|err| format!("Cannot convert array slice {:?}", err))?;

    let mtu = device_link.mtu().expect("Parent device should have an MTU.");

    let ip_network = {
        let address = if device.addresses.len() != 1 {
            return Err(format!(
                "Device with index {} should have only one inet address",
                device_index
            ));
        } else {
            &device.addresses[0]
        };

        let netmask = address
            .netmask
            .expect(&*format!("Device {} address must have a netmask.", &device.name));

        IpNetwork::with_netmask(address.addr, netmask)
            .map_err(|err| format!("Cannot create ip network for device {}. {:?}", &device.name, err))?
    };

    let get_routes_result = netlink.get_routes_for_device(device_index, rtnetlink::IpVersion::V4).await?;

    let gateway = get_routes_result.gateway.map(|e| Gateway::try_from(&e)).transpose()?;

    let routes = {
        let result: Result<Vec<Route>, String> = get_routes_result.routes.iter().map(Route::try_from).collect();

        result?
    };

    let static_arp_entries = get_static_arp_entries(&netlink, device_index).await?;

    let result = NetworkDeviceSettings {
        index: device_index,
        self_l2_address: mac_address,
        self_l3_address: ip_network,
        mtu,
        gateway,
        routes,
        static_arp_entries,
    };

    Ok(result)
}

async fn get_static_arp_entries(netlink: &Netlink, device_index: u32) -> Result<Vec<ARPEntry>, String> {
    let neighbours = netlink.get_neighbours_for_device(device_index).await?;

    let arp_entries_it = neighbours.iter().filter_map(|neighbour| {
        if neighbour.header.state & NUD_PERMANENT != 0 {
            Some(ARPEntry::try_from(neighbour))
        } else {
            None
        }
    });

    arp_entries_it.collect()
}

async fn read_from_device_async(
    mut capture: Fuse<pcap_async::PacketStream>,
    mut enclave_stream: WriteHalf<AsyncVsockStream>,
) -> Result<(), String> {
    let mut count = 0 as u32;
    let mut unsupported_protocols = HashSet::<u8>::new();

    loop {
        let packets = match capture.next().await {
            Some(Ok(packets)) => packets,
            Some(Err(e)) => return Err(format!("Failed to read packet from pcap {:?}", e)),
            None => return Ok(()),
        };

        for packet in packets {
            if packet.actual_length() == packet.original_length() {
                let mut data = packet.into_data();

                match recompute_packet_checksum(&mut data) {
                    Err(ChecksumComputationError::Err(err)) => {
                        warn!("Failed recomputing checksum for a packet. {:?}", err);
                    }
                    Err(ChecksumComputationError::UnsupportedProtocol(protocol)) => {
                        if unsupported_protocols.insert(protocol) {
                            warn!(
                                "Unsupported protocol {} encountered when recomputing checksum for a packet.",
                                protocol
                            );
                        }
                    }
                    _ => {}
                }

                enclave_stream.write_lv_bytes(&data).await?;

                count = log_packet_processing(count, PACKET_LOG_STEP, "parent pcap");
            } else {
                warn!(
                    "Dropped PCAP captured packet! \
                        Reason: captured packet length ({} bytes) \
                        is different than the inbound packet length ({} bytes).",
                    packet.actual_length(),
                    packet.original_length()
                );
            }
        }
    }
}

async fn write_to_device_async(
    mut capture: Capture<Active>,
    mut from_enclave: ReadHalf<AsyncVsockStream>,
) -> Result<(), String> {
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
        let packet = from_enclave
            .read_lv_bytes()
            .await
            .map_err(|err| format!("Failed to read packet from enclave {:?}", err))?;

        match error_rx.try_recv() {
            Err(TryRecvError::Disconnected) => {
                return Err(format!("pcap writer thread died prematurely"));
            }
            Ok(e) => return Err(e),
            _ => {}
        }

        packet_tx
            .send(packet)
            .map_err(|err| format!("Failed to send packet to pcap writer thread {:?}", err))?;

        count = log_packet_processing(count, PACKET_LOG_STEP, "parent vsock");
    }
}

async fn create_vsock_stream(port: u32) -> Result<AsyncVsockStream, String> {
    let mut socket = listen_to_parent(port)?;

    accept(&mut socket).await
}

fn listen_to_parent(port: u32) -> Result<AsyncVsockListener, String> {
    AsyncVsockListener::bind(VSOCK_PARENT_CID, port)
        .map_err(|_| format!("Could not bind to cid: {}, port: {}", VSOCK_PARENT_CID, port))
}

async fn accept(listener: &mut AsyncVsockListener) -> Result<AsyncVsockStream, String> {
    listener
        .accept()
        .await
        .map(|r| r.0)
        .map_err(|err| format!("Accept from vsock failed: {:?}", err))
}

fn get_app_config_id() -> Option<String> {
    match env::var("ENCLAVEOS_APPCONFIG_ID").or(env::var("APPCONFIG_ID")) {
        Ok(result) => Some(result),
        Err(err) => {
            warn!(
                "Failed reading env var ENCLAVEOS_APPCONFIG_ID or APPCONFIG_ID, assuming var is not set. {:?}",
                err
            );
            None
        }
    }
}

fn env_var_or_none(var_name: &str) -> Option<String> {
    match env::var(var_name) {
        Ok(result) => Some(result),
        Err(err) => {
            warn!("Failed reading env var {}, assuming var is not set. {:?}", var_name, err);
            None
        }
    }
}

enum ChecksumComputationError {
    UnsupportedProtocol(u8),
    Err(String),
}

fn recompute_packet_checksum(data: &mut [u8]) -> Result<(), ChecksumComputationError> {
    let ethernet_packet = SlicedPacket::from_ethernet(&data)
        .map_err(|err| ChecksumComputationError::Err(format!("Cannot parse ethernet packet. {:?}", err)))?;

    let l3_checksum = match ethernet_packet.ip {
        Some(Ipv4(ref ip_packet, _)) => {
            let checksum = ip_packet
                .to_header()
                .calc_header_checksum()
                .map_err(|err| ChecksumComputationError::Err(format!("Failed computing IPv4 checksum. {:?}", err)))?;

            let offset = field_offset_in_packet(data, ip_packet.slice(), IPV4_CHECKSUM_FIELD_INDEX);

            Some((offset, checksum))
        }
        // Ipv6 packet doesn't have a checksum
        _ => None,
    };

    let l4_checksum = match (ethernet_packet.ip, ethernet_packet.transport) {
        (Some(Ipv4(ip_packet, _)), Some(Tcp(tcp_packet))) => {
            let checksum = tcp_packet
                .calc_checksum_ipv4(&ip_packet, ethernet_packet.payload)
                .map_err(|err| ChecksumComputationError::Err(format!("Failed computing TCP checksum. {:?}", err)))?;

            let offset = field_offset_in_packet(data, tcp_packet.slice(), TCP_CHECKSUM_FIELD_INDEX);

            Some((offset, checksum))
        }
        (Some(Ipv4(ip_packet, _)), Some(Udp(udp_packet))) => {
            let checksum = udp_packet
                .calc_checksum_ipv4(&ip_packet, ethernet_packet.payload)
                .map_err(|err| ChecksumComputationError::Err(format!("Failed computing UDP checksum. {:?}", err)))?;

            let offset = field_offset_in_packet(data, udp_packet.slice(), UDP_CHECKSUM_FIELD_INDEX);

            Some((offset, checksum))
        }
        (_, Some(Unknown(protocol_number))) => {
            return Err(ChecksumComputationError::UnsupportedProtocol(protocol_number));
        }
        _ => None,
    };

    if let Some((checksum_offset, checksum)) = l3_checksum {
        update_checksum(data, checksum_offset, checksum)
    }

    if let Some((checksum_offset, checksum)) = l4_checksum {
        update_checksum(data, checksum_offset, checksum);
    }

    Ok(())
}

fn update_checksum(packet: &mut [u8], checksum_offset: usize, checksum: u16) -> () {
    let checksum_slice = &mut packet[checksum_offset..(checksum_offset + mem::size_of::<u16>())];

    checksum_slice.copy_from_slice(&checksum.to_be_bytes())
}

/// Computes the offset of a field at index `header_field_index` in `header`
/// relative to the start of `full_packet`.
///
/// # Panics
/// Panics if `header` isn't contained within `full_packet` or if
/// `header_field_index` isn't contained within `header`.
fn field_offset_in_packet<'a>(full_packet: &'a [u8], header: &'a [u8], header_field_index: usize) -> usize {
    assert!(full_packet.len() <= (isize::max_value() as usize)); // assertion 1
    let full_packet = full_packet.as_ptr_range();
    let field = header[header_field_index..].as_ptr_range();
    assert!(full_packet.start <= field.start); // assertion 2
    assert!(field.end <= full_packet.end); // assertion 3
                                           // SAFETY, w.r.t. `field.start` and `full_packet.start`:
                                           // Both pointers are in bounds of the same allocated object (`full_packet`, assertions 2 & 3).
                                           // Both pointers are derived from a pointer to the same object (`full_packet`, assertions 2 & 3).
                                           // The distance between the pointers, in bytes, is an exact multiple of the size of u8 (trivial, as the size is 1).
                                           // The distance between the pointers, in bytes, doesn't overflow an isize (assertion 1).
                                           // The distance between the pointers doesn't wrap around the address space (assertion 2).
    unsafe { field.start.offset_from(full_packet.start) as usize }
}
