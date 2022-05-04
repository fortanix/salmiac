use rtnetlink::packet::NUD_PERMANENT;
use etherparse::InternetSlice::Ipv4;
use etherparse::SlicedPacket;
use etherparse::TransportSlice::{Tcp, Udp, Unknown};
use ipnetwork::IpNetwork;
use nix::net::if_::if_nametoindex;
use pcap::Device;
use tokio_vsock::VsockStream as AsyncVsockStream;
use log::warn;

use shared::netlink::{LinkMessageExt, NetlinkCommon};
use shared::netlink::route::{Gateway, NetlinkRoute};
use shared::netlink::arp::NetlinkARP;
use shared::netlink::Netlink;
use shared::netlink::arp::ARPEntry;
use shared::device::{NetworkDeviceSettings, SetupMessages};
use shared::netlink::route::Route;
use shared::socket::{AsyncWriteLvStream};

use std::convert::TryFrom;
use std::mem;
use crate::parent::{listen_to_parent, accept};

// Byte position of a checksum field in TCP header according to rfc 793 (https://www.ietf.org/rfc/rfc793.txt).
const TCP_CHECKSUM_FIELD_INDEX: usize = 16;

// Byte position of a checksum field in UDP header according to rfc 768 (https://www.ietf.org/rfc/rfc768.txt).
const UDP_CHECKSUM_FIELD_INDEX: usize = 6;

// Byte position of a checksum field in IPv4 header according to rfc 791 (https://www.ietf.org/rfc/rfc791.txt).
const IPV4_CHECKSUM_FIELD_INDEX: usize = 10;


pub(crate) struct PairedPcapDevice {
    pub pcap: Device,

    pub vsock: AsyncVsockStream,
}

pub(crate) async fn setup_network_devices(
    enclave_port: &mut AsyncVsockStream,
    devices: Vec<Device>,
    settings_list: Vec<NetworkDeviceSettings>,
) -> Result<Vec<PairedPcapDevice>, String> {
    let mut device_listeners = Vec::new();

    for settings in &settings_list {
        device_listeners.push(listen_to_parent(settings.vsock_port_number)?);
    }

    enclave_port
        .write_lv(&SetupMessages::NetworkDeviceSettings(settings_list))
        .await?;

    let mut device_streams = Vec::new();

    for mut listener in device_listeners {
        device_streams.push(accept(&mut listener).await?);
    }

    let result = devices
        .into_iter()
        .zip(device_streams.into_iter())
        .map(|e| PairedPcapDevice { pcap: e.0, vsock: e.1 })
        .collect();

    Ok(result)
}

pub(crate) async fn list_network_devices() -> Result<(Vec<Device>, Vec<NetworkDeviceSettings>), String> {
    let netlink = Netlink::new();
    let devices = pcap::Device::list().map_err(|err| format!("Failed retrieving network device list. {:?}", err))?;

    let mut device_settings: Vec<NetworkDeviceSettings> = Vec::new();

    for device in &devices {
        let device_name = device.name.clone();

        if device_name != "lo" && device_name != "any" {
            match get_network_settings_for_device(device, &netlink).await {
                Ok(settings) => {
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

    Ok((devices, device_settings))
}

async fn get_network_settings_for_device(device: &pcap::Device, netlink: &Netlink) -> Result<NetworkDeviceSettings, String> {
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
        vsock_port_number: device_index,
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


pub(crate) enum ChecksumComputationError {
    UnsupportedProtocol(u8),
    Err(String),
}

pub(crate) fn recompute_packet_checksum(data: &mut [u8]) -> Result<(), ChecksumComputationError> {
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