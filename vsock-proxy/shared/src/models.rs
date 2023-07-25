use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::netlink::arp::ARPEntry;
use crate::netlink::route::{Gateway, Route};

use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug)]
pub enum SetupMessages {
    NoMoreCertificates,
    NetworkDeviceSettings(Vec<NetworkDeviceSettings>),
    PrivateNetworkDeviceSettings(PrivateNetworkDeviceSettings),
    GlobalNetworkSettings(GlobalNetworkSettings),
    CSR(String),
    Certificate(String),
    UserProgramExit(Result<UserProgramExitStatus, String>),
    ApplicationConfig(ApplicationConfiguration),
    NBDConfiguration(NBDConfiguration),
    EnvVariables(Vec<(String, String)>),
    ExtraUserProgramArguments(Vec<String>),
    ExitEnclave,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NBDConfiguration {
    pub address: IpAddr,

    pub exports: Vec<NBDExport>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NBDExport {
    pub name: String,

    pub port: u16,
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
    pub vsock_port_number: u32,

    pub self_l2_address: [u8; 6],

    pub self_l3_address: IpNetwork,

    pub name: String,

    pub mtu: u32,

    pub gateway: Option<Gateway>,

    pub routes: Vec<Route>,

    pub static_arp_entries: Vec<ARPEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrivateNetworkDeviceSettings {
    pub vsock_port_number: u32,

    pub l3_address: IpNetwork,

    pub name: String,

    pub mtu: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GlobalNetworkSettings {
    pub hostname: String,

    pub global_settings_list: Vec<FileWithPath>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileWithPath {
    pub path: String,

    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UserProgramExitStatus {
    ExitCode(i32),
    TerminatedBySignal,
}
