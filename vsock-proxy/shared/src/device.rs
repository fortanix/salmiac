use crate::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tokio_vsock::VsockStream as AsyncVsockStream;
use tun::AsyncDevice;

use crate::{log_packet_processing, UserProgramExitStatus, MAX_ETHERNET_HEADER_SIZE, PACKET_LOG_STEP};

use crate::netlink::arp::ARPEntry;
use crate::netlink::route::{Gateway, Route};

use std::net::SocketAddr;

#[derive(Serialize, Deserialize, Debug)]
pub enum SetupMessages {
    NoMoreCertificates,
    NetworkDeviceSettings(Vec<NetworkDeviceSettings>),
    FSNetworkDeviceSettings(FSNetworkDeviceSettings),
    GlobalNetworkSettings(GlobalNetworkSettings),
    CSR(String),
    Certificate(String),
    UserProgramExit(UserProgramExitStatus),
    ApplicationConfig(ApplicationConfiguration),
    UseFileSystem(bool),
    NBDConfiguration(SocketAddr)
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

    pub mtu: u32,

    pub gateway: Option<Gateway>,

    pub routes: Vec<Route>,

    pub static_arp_entries: Vec<ARPEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FSNetworkDeviceSettings {
    pub vsock_port_number: u32,

    pub l3_address: IpNetwork,

    pub mtu: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GlobalNetworkSettings {
    pub dns_file: Vec<u8>,
}

pub fn create_async_tap_device(config: &tun::Configuration) -> Result<AsyncDevice, String> {
    tun::create_as_async(config).map_err(|err| format!("Cannot create async tap device {:?}", err))
}

pub fn tap_device_config(l3_address: &IpNetwork, mtu: u32) -> tun::Configuration {
    let mut config = tun::Configuration::default();

    config
        .address(l3_address.ip())
        .netmask(l3_address.mask())
        .layer(tun::Layer::L2)
        .mtu(mtu as i32)
        .up();

    config
}

impl From<&NetworkDeviceSettings> for tun::Configuration {
    fn from(arg: &NetworkDeviceSettings) -> Self {
        tap_device_config(&arg.self_l3_address, arg.mtu)
    }
}

pub struct TapLoopsResult {
    pub read_handle: JoinHandle<Result<(), String>>,

    pub write_handle: JoinHandle<Result<(), String>>,
}

pub fn start_tap_loops(tap_device: AsyncDevice, vsock: AsyncVsockStream, mtu: u32) -> TapLoopsResult {
    let (tap_read, tap_write) = io::split(tap_device);
    let (vsock_read, vsock_write) = io::split(vsock);

    let read_handle = tokio::spawn(read_from_tap_async(tap_read, vsock_write, mtu));

    let write_handle = tokio::spawn(write_to_tap_async(tap_write, vsock_read));

    TapLoopsResult {
        read_handle,
        write_handle,
    }
}

async fn read_from_tap_async(
    mut device: ReadHalf<AsyncDevice>,
    mut vsock: WriteHalf<AsyncVsockStream>,
    buf_len: u32,
) -> Result<(), String> {
    let mut buf = vec![0 as u8; (MAX_ETHERNET_HEADER_SIZE + buf_len) as usize];
    let mut count = 0 as u32;

    loop {
        let amount = AsyncReadExt::read(&mut device, &mut buf)
            .await
            .map_err(|err| format!("Cannot read from tap {:?}", err))?;

        vsock
            .write_lv_bytes(&buf[..amount])
            .await
            .map_err(|err| format!("Failed to write to enclave vsock {:?}", err))?;

        count = log_packet_processing(count, PACKET_LOG_STEP, "enclave tap");
    }
}

async fn write_to_tap_async(mut device: WriteHalf<AsyncDevice>, mut vsock: ReadHalf<AsyncVsockStream>) -> Result<(), String> {
    let mut count = 0 as u32;

    loop {
        let packet = vsock.read_lv_bytes().await?;

        AsyncWriteExt::write_all(&mut device, &packet)
            .await
            .map_err(|err| format!("Cannot write to tap {:?}", err))?;

        count = log_packet_processing(count, PACKET_LOG_STEP, "enclave vsock");
    }
}
