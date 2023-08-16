use std::convert::{From, TryFrom};
use std::mem;
use std::net::{IpAddr, Ipv4Addr};

use etherparse::InternetSlice::Ipv4;
use etherparse::SlicedPacket;
use etherparse::TransportSlice::{Tcp, Udp, Unknown};
use ipnetwork::{IpNetwork, Ipv4Network};
use log::warn;
use nix::net::if_::if_nametoindex;
use pcap::{Device, Address};
use rtnetlink::packet::NUD_PERMANENT;
use shared::models::{PrivateNetworkDeviceSettings, NetworkDeviceSettings, SetupMessages};
use shared::netlink::arp::{ARPEntry, NetlinkARP};
use shared::netlink::route::{Gateway, NetlinkRoute, Route};
use shared::netlink::{LinkMessageExt, Netlink, NetlinkCommon};
use shared::socket::AsyncWriteLvStream;
use shared::tap::{create_async_tap_device, PRIVATE_TAP_MTU, tap_device_config};
use tokio_vsock::VsockStream as AsyncVsockStream;
use tun::AsyncDevice;

use crate::parent::{accept, listen_to_parent};

// Byte position of a checksum field in TCP header according to rfc 793 (https://www.ietf.org/rfc/rfc793.txt).
const TCP_CHECKSUM_FIELD_INDEX: usize = 16;

// Byte position of a checksum field in UDP header according to rfc 768 (https://www.ietf.org/rfc/rfc768.txt).
const UDP_CHECKSUM_FIELD_INDEX: usize = 6;

// Byte position of a checksum field in IPv4 header according to rfc 791 (https://www.ietf.org/rfc/rfc791.txt).
const IPV4_CHECKSUM_FIELD_INDEX: usize = 10;

// Prefix size that allows only 2 addresses in a network
const FS_TAP_NETWORK_PREFIX_SIZE: u8 = 30;


pub(crate) struct PairedPcapDevice {
    pub(crate) pcap: Device,

    pub(crate) vsock: AsyncVsockStream,
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
                        "Network settings for device {} could not be obtained, device won't be setup! {}",
                        device_name, e
                    )
                }
            };
        }
    }

    Ok((devices, device_settings))
}

async fn get_network_settings_for_device<D, N>(device: &D, netlink: &N) -> Result<NetworkDeviceSettings, String>
where D: NetworkDevice, N: NetlinkCommon + NetlinkARP + NetlinkRoute {
    let device_name = device.name();
    let device_index = device.index()?;

    let device_link = netlink
        .get_link_for_device(device_index)
        .await?
        .ok_or(&format!("Device {} must have a link.", device_name))?;

    let mac_address = device_link
        .address()
        .map(|e| <[u8; 6]>::try_from(&e[..]))
        .ok_or(&*format!("Parent link in device {} should have an address.", device_name))?
        .map_err(|err| format!("Cannot convert array slice {:?}. Network device is {}", err, device_name))?;

    let mtu = device_link
        .mtu()
        .expect(&*format!("Parent device {} should have an MTU.", device_name));

    let ip_network = device.ip_network()?;

    let get_routes_result = netlink.get_routes_for_device(device_index, rtnetlink::IpVersion::V4).await?;

    let gateway = get_routes_result.gateway.map(|e| Gateway::try_from(&e)).transpose()?;

    let routes = {
        let result: Result<Vec<Route>, String> = get_routes_result.routes.iter().map(Route::try_from).collect();

        result?
    };

    let static_arp_entries = get_static_arp_entries(netlink, device_index).await?;

    let result = NetworkDeviceSettings {
        vsock_port_number: device_index,
        self_l2_address: mac_address,
        self_l3_address: ip_network,
        name: device.name().to_string(),
        mtu,
        gateway,
        routes,
        static_arp_entries,
    };

    Ok(result)
}

async fn get_static_arp_entries<N>(netlink: &N, device_index: u32) -> Result<Vec<ARPEntry>, String> where N: NetlinkARP {
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
                                           // Both pointers are in bounds of the same allocated object (`full_packet`,
                                           // assertions 2 & 3). Both pointers
                                           // are derived from a pointer to the same object (`full_packet`, assertions 2 &
                                           // 3). The distance between the
                                           // pointers, in bytes, is an exact multiple of the size of u8 (trivial, as the
                                           // size is 1). The distance between
                                           // the pointers, in bytes, doesn't overflow an isize (assertion 1).
                                           // The distance between the pointers doesn't wrap around the address space
                                           // (assertion 2).
    unsafe { field.start.offset_from(full_packet.start) as usize }
}

pub(crate) struct PairedTapDevice {
    pub(crate) tap: AsyncDevice,

    pub(crate) tap_l3_address: IpNetwork,

    pub(crate) vsock: AsyncVsockStream,
}

pub(crate) async fn set_up_private_tap_devices(
    enclave_port: &mut AsyncVsockStream,
    parent_address: IpNetwork,
    parent_dev_name: &str,
    enclave_address: IpNetwork,
    enclave_dev_name: &str,
) -> Result<PairedTapDevice, String> {
    let device = create_async_tap_device(&tap_device_config(&parent_address, parent_dev_name, PRIVATE_TAP_MTU))?;

    use tun::Device;
    let tap_index =
        if_nametoindex(device.get_ref().name()).map_err(|err| format!("Cannot find index for tap device {:?}", err))?;

    let mut listener = listen_to_parent(tap_index)?;

    let private_tap_settings = PrivateNetworkDeviceSettings {
        vsock_port_number: tap_index,
        l3_address: enclave_address,
        name: enclave_dev_name.to_string(),
        mtu: PRIVATE_TAP_MTU,
    };

    enclave_port
        .write_lv(&SetupMessages::PrivateNetworkDeviceSettings(private_tap_settings))
        .await?;

    let vsock = accept(&mut listener).await?;

    Ok(PairedTapDevice {
        tap: device,
        tap_l3_address: parent_address,
        vsock,
    })
}

/// Returns first available pair of free addresses inside a private network
/// range that are not present in `in_use` `Vec`. We use said addresses to
/// create an isolated private network for enclave-parent communication.
///
/// In detail the function performs a linear search among the 3 ranges of
/// private network addresses (https://en.wikipedia.org/wiki/Private_network) and returns when it finds 2 ip addresses
/// that are not contained in `in_use` `Vec`.
/// # Arguments
/// `in_use` - a `Vec` of ip addresses that are already in use by other network
/// devices
/// # Returns
/// A pair of addresses, where first value is parent's address and second one is
/// enclave's address.
///
/// TODO: We should use IPv6 addresses instead of IPv4 addresses for the private network.
pub(crate) fn choose_addrs_for_private_taps(in_use: Vec<Ipv4Network>) -> Result<(IpNetwork, IpNetwork), String> {
    let private_networks: [Ipv4Network; 3] = [
        Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 0), FS_TAP_NETWORK_PREFIX_SIZE).expect(""),
        Ipv4Network::new(Ipv4Addr::new(172, 16, 0, 0), FS_TAP_NETWORK_PREFIX_SIZE).expect(""),
        Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 0), FS_TAP_NETWORK_PREFIX_SIZE).expect(""),
    ];

    for private_network in private_networks {
        if !in_use.iter().any(|e| e.overlaps(private_network)) {
            let network_id = u32::from(private_network.network());

            let parent_address: Ipv4Addr = (network_id + 1).into();
            let enclave_address: Ipv4Addr = (network_id + 2).into();

            let parent_network = IpNetwork::new(IpAddr::V4(parent_address), FS_TAP_NETWORK_PREFIX_SIZE).expect("");
            let enclave_network = IpNetwork::new(IpAddr::V4(enclave_address), FS_TAP_NETWORK_PREFIX_SIZE).expect("");

            return Ok((parent_network, enclave_network));
        }
    }

    Err(format!(
        "Couldn't find 2 free addresses for file system tap devices among {:?} private networks",
        private_networks
    ))
}

trait NetworkDevice {
    fn name(&self) -> &str;

    fn addresses(&self) -> &Vec<Address>;

    fn index(&self) -> Result<u32, String>  {
        let device_name = self.name();

        if_nametoindex(device_name).map_err(|err| format!("Cannot find index for device {}, error {:?}", device_name, err))
    }

    fn ip_network(&self) -> Result<IpNetwork, String> {
        fn addresses_to_string(addresses: &[Address]) -> String {
            addresses
                .iter()
                .map(|e| e.addr.to_string())
                .collect::<Vec<_>>()
                .join(",")
        }

        let device_name = self.name();
        let assigned_addresses = self.addresses();

        let address = assigned_addresses
            .iter()
            .find(|e| e.addr.is_ipv4())
            .ok_or(
                format!("Cannot find an IpV4 address for device {}. Device address list is {:?}", device_name, addresses_to_string(&assigned_addresses)))?;

        let netmask = address
            .netmask
            .ok_or(&*format!("Device {} address must have a netmask.", device_name))?;

        IpNetwork::with_netmask(address.addr, netmask)
            .map_err(|err| format!("Cannot create ip network for device {}. {:?}", device_name, err))
    }
}

impl NetworkDevice for pcap::Device {
    fn name(&self) -> &str {
        &self.name
    }

    fn addresses(&self) -> &Vec<Address> {
        &self.addresses
    }
}

#[cfg(test)]
mod tests {
    use crate::network::NetworkDevice;
    use pcap::Address;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use ipnetwork::{IpNetwork, Ipv4Network};

    #[derive(Debug)]
    struct TestNetworkDevice {
        pub addresses_data: Vec<Address>
    }

    impl NetworkDevice for TestNetworkDevice {
        fn name(&self) -> &str {
            "test"
        }

        fn addresses(&self) -> &Vec<Address> {
            &self.addresses_data
        }
    }

    #[test]
    fn ip_network_incorrect_pass() {
        let no_addresses = TestNetworkDevice { addresses_data: vec![] };
        let no_netmask = TestNetworkDevice { addresses_data: vec![Address {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            netmask: None,
            broadcast_addr: None,
            dst_addr: None
        }] };
        let no_ipv4_address = TestNetworkDevice {
            addresses_data: vec![Address {
                addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                netmask: None,
                broadcast_addr: None,
                dst_addr: None
            }]
        };

        assert!(no_addresses.ip_network().is_err(), "Ip network should fail when there is no addresses present. {:?}", no_addresses);
        assert!(no_netmask.ip_network().is_err(), "Ip network should fail when there is no netmask for address. {:?}", no_netmask);
        assert!(no_ipv4_address.ip_network().is_err(), "Ip network should fail when there is no ipv4 address. {:?}", no_ipv4_address)
    }

    #[test]
    fn ip_network_correct_pass() {
        let ip_address = Ipv4Addr::LOCALHOST;
        let netmask = Ipv4Addr::new(0,0,0,0);

        let device = TestNetworkDevice { addresses_data: vec![Address {
            addr: IpAddr::V4(ip_address.clone()),
            netmask: Some(IpAddr::V4(netmask.clone())),
            broadcast_addr: None,
            dst_addr: None
        }] };

        let result = device.ip_network().expect("ip network failed");
        let reference = IpNetwork::V4(Ipv4Network::with_netmask(ip_address, netmask).expect("ipv4 network ctor failed"));

        assert_eq!(result, reference)
    }
}
