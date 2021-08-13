use serde::{
    Serialize,
    Deserialize
};
use pnet_datalink::{
    NetworkInterface,
    MacAddr
};
use tun::platform::linux::Device as TunDevice;
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug)]
pub enum SetupMessages {
    SetupSuccessful,
    Settings(NetworkSettings)
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "pnet_datalink::MacAddr")]
struct MacAddrDefinition(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkSettings {
    pub ip_address : IpAddr,

    pub netmask : IpAddr,

    #[serde(with = "MacAddrDefinition")]
    pub mac_address : MacAddr,

    pub gateway_address : IpAddr,

    #[serde(with = "MacAddrDefinition")]
    pub link_local_address : MacAddr
}

pub fn get_default_network_device() -> Option<NetworkInterface> {
    pnet_datalink::interfaces()
        .into_iter()
        .find(|e| {
            e.is_up() && !e.is_loopback() && !e.ips.is_empty() && e.mac.is_some()
        })
}

pub fn create_tap_device(parent_settings : &NetworkSettings) -> Result<TunDevice, String> {
    let mut config = tun::Configuration::default();

    config.address(IpAddr::from(parent_settings.ip_address))
        .netmask(IpAddr::from(parent_settings.netmask))
        .layer(tun::Layer::L2)
        .up();

    tun::create(&config).map_err(|err| format!("Cannot create tap device {:?}", err))
}