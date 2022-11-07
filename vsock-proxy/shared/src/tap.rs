use crate::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use ipnetwork::IpNetwork;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tokio_vsock::VsockStream as AsyncVsockStream;
use tun::AsyncDevice;

use crate::models::NetworkDeviceSettings;
use crate::MAX_ETHERNET_HEADER_SIZE;

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
    pub tap_to_vsock: JoinHandle<Result<(), String>>,

    pub vsock_to_tap: JoinHandle<Result<(), String>>,
}

/// Starts two network forwarding tasks which allow networking to function inside an enclave.
/// One task forwards packets from tap device and into the vsock and other does the same in the opposite direction.
/// Network forwarding tasks never exit during normal enclave execution and it is considered an error if they do.
/// # Returns
/// Handles to two network forwarding tasks
pub fn start_tap_loops(tap_device: AsyncDevice, vsock: AsyncVsockStream, mtu: u32) -> TapLoopsResult {
    let (tap_read, tap_write) = io::split(tap_device);
    let (vsock_read, vsock_write) = io::split(vsock);

    let tap_to_vsock = tokio::spawn(read_from_tap_async(tap_read, vsock_write, mtu));

    let vsock_to_tap = tokio::spawn(write_to_tap_async(tap_write, vsock_read));

    TapLoopsResult {
        tap_to_vsock,
        vsock_to_tap,
    }
}

async fn read_from_tap_async(
    mut device: ReadHalf<AsyncDevice>,
    mut vsock: WriteHalf<AsyncVsockStream>,
    buf_len: u32,
) -> Result<(), String> {
    let mut buf = vec![0 as u8; (MAX_ETHERNET_HEADER_SIZE + buf_len) as usize];

    loop {
        let amount = AsyncReadExt::read(&mut device, &mut buf)
            .await
            .map_err(|err| format!("Cannot read from tap {:?}", err))?;

        vsock
            .write_lv_bytes(&buf[..amount])
            .await
            .map_err(|err| format!("Failed to write to enclave vsock {:?}", err))?;
    }
}

async fn write_to_tap_async(mut device: WriteHalf<AsyncDevice>, mut vsock: ReadHalf<AsyncVsockStream>) -> Result<(), String> {
    loop {
        let packet = vsock.read_lv_bytes().await?;

        AsyncWriteExt::write_all(&mut device, &packet)
            .await
            .map_err(|err| format!("Cannot write to tap {:?}", err))?;
    }
}
