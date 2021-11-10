use serde::{
    Serialize,
    Deserialize
};
use ipnetwork::IpNetwork;
use tun::{AsyncDevice};
use tun::platform::linux::Device as TapDevice;

use crate::UserProgramExitStatus;

use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug)]
pub enum SetupMessages {
    SetupSuccessful,
    Settings(NetworkSettings),
    CSR(String),
    Certificate(String),
    UserProgramExit(UserProgramExitStatus)
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkSettings {
    pub self_l2_address: [u8; 6],

    pub self_l3_address: IpNetwork,

    pub gateway_l3_address: IpAddr,

    pub mtu : u32
}

pub fn create_tap_device(parent_settings : &NetworkSettings) -> Result<TapDevice, String> {
    tun::create(&tap_device_config(parent_settings))
        .map_err(|err| format!("Cannot create tap device {:?}", err))
}

pub fn create_async_tap_device(parent_settings : &NetworkSettings) -> Result<AsyncDevice, String> {
    tun::create_as_async(&tap_device_config(parent_settings))
        .map_err(|err| format!("Cannot create async tap device {:?}", err))
}

fn tap_device_config(parent_settings : &NetworkSettings) -> tun::Configuration {
    let mut config = tun::Configuration::default();

    config.address(parent_settings.self_l3_address.ip())
        .netmask(parent_settings.self_l3_address.mask())
        .layer(tun::Layer::L2)
        .mtu(parent_settings.mtu as i32)
        .up();

    config
}
