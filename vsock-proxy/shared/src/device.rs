use serde::{
    Serialize,
    Deserialize
};

use tun::platform::linux::Device as TunDevice;
use std::net::IpAddr;
use ipnetwork::IpNetwork;

#[derive(Serialize, Deserialize, Debug)]
pub enum SetupMessages {
    SetupSuccessful,
    Settings(NetworkSettings)
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkSettings {
    pub self_l2_address: [u8; 6],

    pub self_l3_address: IpNetwork,

    pub gateway_l2_address: IpAddr,

    pub gateway_l3_address: [u8; 6],

    pub mtu : u32
}

pub fn create_tap_device(parent_settings : &NetworkSettings) -> Result<TunDevice, String> {
    let mut config = tun::Configuration::default();

    config.address(parent_settings.self_l3_address.ip())
        .netmask(parent_settings.self_l3_address.mask())
        .layer(tun::Layer::L2)
        .mtu(parent_settings.mtu as i32)
        .up();

    tun::create(&config).map_err(|err| format!("Cannot create tap device {:?}", err))
}
