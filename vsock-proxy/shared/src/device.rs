use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tun::platform::linux::Device as TapDevice;
use tun::AsyncDevice;

use crate::UserProgramExitStatus;

use crate::netlink::arp::ARPEntry;
use crate::netlink::route::{Gateway, Route};

#[derive(Serialize, Deserialize, Debug)]
pub enum SetupMessages {
    SetupSuccessful,
    NetworkDeviceSettings(Vec<NetworkDeviceSettings>),
    GlobalNetworkSettings(GlobalNetworkSettings),
    CSR(String),
    Certificate(String),
    UserProgramExit(UserProgramExitStatus),
    ApplicationConfig(ApplicationConfiguration),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApplicationConfiguration {
    pub id: Option<String>,

    pub ccm_backend_url: CCMBackendUrl,

    pub skip_server_verify: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CCMBackendUrl {
    pub host: String,

    pub port: u16,
}

impl CCMBackendUrl {
    pub fn new(url: &str) -> Result<Self, String> {
        let split: Vec<_> = url.split(":").collect();

        if split.len() != 2 {
            return Err("CCM_BACKEND should be in format <ip address>:<port>".to_string());
        }

        match split[1].parse::<u16>() {
            Err(err) => Err(format!("CCM_BACKEND port should be a number. {:?}", err)),
            Ok(port) => Ok(CCMBackendUrl {
                host: split[0].to_string(),
                port,
            }),
        }
    }
}

impl Default for CCMBackendUrl {
    fn default() -> Self {
        CCMBackendUrl {
            host: "ccm.fortanix.com".to_string(),
            port: 443,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkDeviceSettings {
    pub index: u32,

    pub self_l2_address: [u8; 6],

    pub self_l3_address: IpNetwork,

    pub mtu: u32,

    pub gateway: Option<Gateway>,

    pub routes: Vec<Route>,

    pub static_arp_entries: Vec<ARPEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GlobalNetworkSettings {
    pub dns_file: Vec<u8>,
}

pub fn create_tap_device(parent_settings: &NetworkDeviceSettings) -> Result<TapDevice, String> {
    tun::create(&tap_device_config(parent_settings)).map_err(|err| format!("Cannot create tap device {:?}", err))
}

pub fn create_async_tap_device(parent_settings: &NetworkDeviceSettings) -> Result<AsyncDevice, String> {
    tun::create_as_async(&tap_device_config(parent_settings)).map_err(|err| format!("Cannot create async tap device {:?}", err))
}

fn tap_device_config(parent_settings: &NetworkDeviceSettings) -> tun::Configuration {
    let mut config = tun::Configuration::default();

    config
        .address(parent_settings.self_l3_address.ip())
        .netmask(parent_settings.self_l3_address.mask())
        .layer(tun::Layer::L2)
        .mtu(parent_settings.mtu as i32)
        .up();

    config
}
