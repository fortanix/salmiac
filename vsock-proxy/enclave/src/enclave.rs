use log::{debug, info};
use nix::net::if_::if_nametoindex;
use tokio_vsock::VsockStream as AsyncVsockStream;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tun::AsyncDevice;

use shared::device::{NetworkSettings, SetupMessages};
use shared::{VSOCK_PARENT_CID, DATA_SOCKET, PACKET_LOG_STEP, log_packet_processing};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};

use std::net::IpAddr;

pub async fn run(vsock_port: u32) -> Result<(), String> {
    let mut parent_settings_connection = connect_to_parent_async(vsock_port).await?;

    info!("Connected to parent!");

    let parent_data_connection = connect_to_parent_async(DATA_SOCKET).await?;

    info!("Connected to parent to transmit data!");

    let parent_settings = receive_parent_network_settings(&mut parent_settings_connection).await?;

    let async_tap_device = setup_enclave_networking(&mut parent_settings_connection, &parent_settings).await?;

    info!("Created tap device in enclave!");

    let (tap_read, tap_write) = io::split(async_tap_device);
    let (vsock_read, vsock_write) = io::split(parent_data_connection);

    let mtu = parent_settings.mtu;

    let read_tap_loop = tokio::spawn(read_from_tap_async(tap_read, vsock_write, mtu));

    debug!("Started tap read loop!");

    let write_tap_loop = tokio::spawn(write_to_tap_async(tap_write, vsock_read));

    debug!("Started tap write loop!");

    match tokio::try_join!(read_tap_loop, write_tap_loop) {
        Ok((read_returned, write_returned)) => {
            read_returned.map_err(|err| format!("Failure in tap read loop: {:?}", err))?;
            write_returned.map_err(|err| format!("Failure in tap write loop: {:?}", err))
        }
        Err(err) => {
            Err(format!("{:?}", err))
        }
    }
}

async fn read_from_tap_async(mut device: ReadHalf<AsyncDevice>, mut vsock : WriteHalf<AsyncVsockStream>, buf_len : u32) -> Result<(), String> {
    let mut buf = vec![0 as u8; buf_len as usize];
    let mut count = 0 as u32;

    loop {
        let amount = AsyncReadExt::read(&mut device, &mut buf)
            .await
            .map_err(|err| format!("Cannot read from tap {:?}", err))?;

        vsock.write_lv_bytes(&buf[..amount])
            .await
            .map_err(|err| format!("Failed to write to enclave vsock {:?}", err))?;

        count = log_packet_processing(count, PACKET_LOG_STEP, "enclave tap");
    }
}

async fn write_to_tap_async(mut device: WriteHalf<AsyncDevice>, mut vsock : ReadHalf<AsyncVsockStream>) -> Result<(), String> {
    let mut count = 0 as u32;

    loop {
        let packet = vsock.read_lv_bytes().await?;

        AsyncWriteExt::write_all(&mut device, &packet)
            .await
            .map_err(|err| format!("Cannot write to tap {:?}", err))?;

        count = log_packet_processing(count, PACKET_LOG_STEP, "enclave vsock");
    }
}

async fn receive_parent_network_settings(vsock : &mut AsyncVsockStream) -> Result<NetworkSettings, String> {
    let msg : SetupMessages = vsock.read_lv().await?;

    match msg {
        SetupMessages::Settings(s) => { Ok(s) }
        x => {
            return Err(format!("Expected SetupMessages::Settings, but got {:?}", x))
        }
    }
}

async fn setup_enclave_networking(vsock : &mut AsyncVsockStream, parent_settings : &NetworkSettings) -> Result<AsyncDevice, String> {
    let tap_device = shared::device::create_async_tap_device(&parent_settings)?;

    debug!("Received next settings from parent {:?}", parent_settings);

    setup_enclave_networking0(&tap_device, &parent_settings).await?;

    info!("Finished network setup!");

    vsock.write_lv(&SetupMessages::SetupSuccessful).await?;

    Ok(tap_device)
}

async fn setup_enclave_networking0(tap_device : &AsyncDevice, parent_settings : &NetworkSettings) -> Result<(), String> {
    use shared::netlink;
    use tun::Device;

    let (netlink_connection, netlink_handle) = netlink::connect();
    tokio::spawn(netlink_connection);

    debug!("Connected to netlink");

    let tap_index = if_nametoindex(tap_device.get_ref().name()).map_err(|err| format!("Cannot find index for tap device {:?}", err))?;

    debug!("Tap index {}", tap_index);

    netlink::set_link(&netlink_handle, tap_index, &parent_settings.self_l2_address).await?;
    info!("MAC address for tap is set!");

    let gateway_addr = parent_settings.gateway_l3_address;
    let as_ipv4 = match gateway_addr {
        IpAddr::V4(e) => {
            e
        }
        _ => {
            return Err("Only IP v4 is supported for gateway".to_string())
        }
    };

    netlink::add_default_gateway(&netlink_handle, as_ipv4).await?;
    info!("Gateway is set!");

    Ok(())
}

async fn connect_to_parent_async(port : u32) -> Result<AsyncVsockStream, String> {
    AsyncVsockStream::connect(VSOCK_PARENT_CID, port)
        .await
        .map_err(|err| format!("Failed to connect to enclave: {:?}", err))
}
