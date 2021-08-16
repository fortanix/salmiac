use serde::{
    Serialize,
    Deserialize
};
use pnet_datalink::{
    NetworkInterface,
};

use tun::platform::linux::Device as TunDevice;
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug)]
pub enum SetupMessages {
    SetupSuccessful,
    Settings(NetworkSettings)
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkSettings {
    pub ip_address : IpAddr,

    pub netmask : IpAddr,

    pub mac_address : Vec<u8>,

    pub gateway_address : IpAddr,

    pub link_local_address : Vec<u8>,

    pub mtu : i32
}

pub struct RichNetworkInterface(pub NetworkInterface);

impl RichNetworkInterface {
    pub fn get_mtu(&self) -> Result<i32, String> {
        let iface = interfaces::Interface::get_by_name(&self.0.name)
            .unwrap()
            .unwrap();

        iface.get_mtu()
            .map(|e| e as i32)
            .map_err(|err| format!("Cannot get device {} MTU, error {:?}", &self.0.name, err))
    }
}

pub fn get_default_network_device() -> Option<RichNetworkInterface> {
    pnet_datalink::interfaces()
        .into_iter()
        .find_map(|e| {
            if e.is_up() && !e.is_loopback() && !e.ips.is_empty() && e.mac.is_some() {
                Some(RichNetworkInterface(e))
            }
            else {
                None
            }
        })
}

pub fn create_tap_device(parent_settings : &NetworkSettings) -> Result<TunDevice, String> {
    let mut config = tun::Configuration::default();

    config.address(IpAddr::from(parent_settings.ip_address))
        .netmask(IpAddr::from(parent_settings.netmask))
        .layer(tun::Layer::L2)
        .mtu(parent_settings.mtu)
        .up();

    tun::create(&config).map_err(|err| format!("Cannot create tap device {:?}", err))
}