use serde::{Serialize, Deserialize};
use pnet_datalink::NetworkInterface;

#[derive(Serialize, Deserialize, Debug)]
pub enum SetupMessages {
    Done,
    Settings(NetworkSettings)
}

#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkSettings {
    pub mac_address : [u8; 6],

    pub gateway_address : [u8; 4],

    pub link_local_address : [u8; 6]
}

pub fn get_default_network_device() -> Option<NetworkInterface> {
    pnet_datalink::interfaces()
        .into_iter()
        .find(|e| {
            e.is_up() && !e.is_loopback() && !e.ips.is_empty() && e.mac.is_some()
        })
}