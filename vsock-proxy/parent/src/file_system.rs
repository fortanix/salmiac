use ipnetwork::{IpNetwork, Ipv4Network};
use nix::net::if_::if_nametoindex;
use tun::AsyncDevice;
use tokio_vsock::VsockStream as AsyncVsockStream;

use shared::device::{create_async_tap_device, tap_device_config, FSNetworkDeviceSettings, SetupMessages};
use shared::socket::{AsyncWriteLvStream};
use crate::parent::{listen_to_parent, accept};

use std::net::{Ipv4Addr, IpAddr};

pub const FS_TAP_MTU: u32 = 9001;

const FS_TAP_NETWORK_PREFIX_SIZE: u8 = 30;

pub(crate) struct PairedTapDevice {
    pub tap: AsyncDevice,

    pub vsock: AsyncVsockStream,
}

pub(crate) async fn setup_file_system_tap_devices(
    enclave_port: &mut AsyncVsockStream,
    parent_address: IpNetwork,
    enclave_address: IpNetwork,
) -> Result<PairedTapDevice, String> {
    let device = create_async_tap_device(&tap_device_config(&parent_address, FS_TAP_MTU))?;

    use tun::Device;
    let tap_index =
        if_nametoindex(device.get_ref().name()).map_err(|err| format!("Cannot find index for tap device {:?}", err))?;

    let mut listener = listen_to_parent(tap_index)?;

    let fs_tap_settings = FSNetworkDeviceSettings {
        vsock_port_number: tap_index,
        l3_address: enclave_address,
        mtu: FS_TAP_MTU,
    };

    enclave_port
        .write_lv(&SetupMessages::FSNetworkDeviceSettings(fs_tap_settings))
        .await?;

    let vsock = accept(&mut listener).await?;

    Ok(PairedTapDevice { tap: device, vsock })
}

/// Returns first available pair of free addresses inside a private network range that are not present in `in_use` `Vec`.
/// We use said addresses to create an isolated private network for enclave-parent communication.
///
/// In detail the function performs a linear search among the 3 ranges of private network addresses
/// (https://en.wikipedia.org/wiki/Private_network) and returns when it finds 2 ip addresses
/// that are not contained in `in_use` `Vec`.
/// # Arguments
/// `in_use` - a `Vec` of ip addresses that are already in use by other network devices
/// # Returns
/// A pair of addresses, where first value is parent's address and second one is enclave's address.
pub(crate) fn choose_network_addresses_for_fs_taps(in_use: Vec<IpNetwork>) -> Result<(IpNetwork, IpNetwork), String> {
    let private_networks: [IpNetwork; 3] = [
        IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 0), FS_TAP_NETWORK_PREFIX_SIZE).expect("")),
        IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(172, 16, 0, 0), FS_TAP_NETWORK_PREFIX_SIZE).expect("")),
        IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 0), FS_TAP_NETWORK_PREFIX_SIZE).expect("")),
    ];

    let mut parent_tap_address = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let mut enclave_tap_address = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    for private_network in private_networks {
        for address in private_network.iter() {
            // network id (lowest possible ip address in a network) cannot be assigned to a device,
            // so we filter it out
            if address != private_network.network() && !in_use.iter().any(|e| e.contains(address)) {
                if parent_tap_address == Ipv4Addr::UNSPECIFIED {
                    parent_tap_address = address;
                } else if enclave_tap_address == Ipv4Addr::UNSPECIFIED {
                    enclave_tap_address = address;
                } else {
                    let parent_network = IpNetwork::new(parent_tap_address, FS_TAP_NETWORK_PREFIX_SIZE).expect("");
                    let enclave_network = IpNetwork::new(enclave_tap_address, FS_TAP_NETWORK_PREFIX_SIZE).expect("");

                    return Ok((parent_network, enclave_network));
                }
            }
        }
    }

    Err(format!(
        "Couldn't find 2 free addresses for file system tap devices among {:?} private networks",
        private_networks
    ))
}