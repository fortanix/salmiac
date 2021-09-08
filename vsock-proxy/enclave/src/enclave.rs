use log::{debug, info};
use nix::net::if_::if_nametoindex;
use nix::sys::socket::SockAddr;
use tokio_vsock::VsockStream as AsyncVsockStream;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tun::AsyncDevice;
#[cfg(feature = "sync")]
use tun::platform::linux::Device;
use vsock::VsockStream;

use shared::device::{NetworkSettings, SetupMessages};
use shared::{VSOCK_PARENT_CID};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream, LvStream};

use std::net::IpAddr;
#[cfg(feature = "sync")]
use std::sync;

pub async fn run(vsock_port: u32) -> Result<(), String> {
    let mut parent_settings_connection = connect_to_parent(vsock_port)?;

    info!("Connected to parent!");

    let parent_data_connection = connect_to_parent_async(100).await?;

    info!("Connected to parent to transmit data!");

    let parent_settings = receive_parent_network_settings(&mut parent_settings_connection)?;

    let async_tap_device = setup_enclave_networking(&mut parent_settings_connection, &parent_settings).await?;

    info!("Created tap device in enclave!");

    let (mut tap_read, mut tap_write) = io::split(async_tap_device);
    let (mut vsock_read, mut vsock_write) = io::split(parent_data_connection);

    let mtu = parent_settings.mtu;

    let read_tap_loop = tokio::spawn(async move {
        loop {
            if let Err(e) = read_from_tap_async(&mut tap_read, &mut vsock_write, mtu).await {
                return Err(e);
            }
        }
    });

    debug!("Started tap read loop!");

    let write_tap_loop = tokio::spawn(async move {
        loop {
            if let Err(e) = write_to_tap_async(&mut tap_write, &mut vsock_read).await {
                return Err(e);
            }
        }
    });

    debug!("Started tap write loop!");

    let (read_returned, write_returned) = tokio::join!(read_tap_loop, write_tap_loop);

    read_returned.map_err(|err| format!("Failure in tap read loop: {:?}", err))??;
    write_returned.map_err(|err| format!("Failure in tap write loop: {:?}", err))??;

    Ok(())
}

async fn read_from_tap_async(device: &mut ReadHalf<AsyncDevice>, vsock : &mut WriteHalf<AsyncVsockStream>, buf_len : u32) -> Result<(), String> {

    let mut buf = vec![0 as u8; buf_len as usize];

    let amount = AsyncReadExt::read(device, &mut buf)
        .await
        .map_err(|err| format!("Cannot read from tap {:?}", err))?;

    buf.truncate(amount);

    debug!("Read packet from tap! {:?}", buf);

    vsock.write_lv_bytes_async(&buf)
        .await
        .map_err(|err| format!("Failed to write to enclave vsock {:?}", err))?;

    debug!("Sent packet to parent!");

    Ok(())
}

async fn write_to_tap_async(device: &mut WriteHalf<AsyncDevice>, vsock : &mut ReadHalf<AsyncVsockStream>) -> Result<(), String> {
    let packet = vsock.read_lv_bytes_async().await?;

    debug!("Received packet from parent! {:?}", packet);

    let size_written = AsyncWriteExt::write(device, &packet)
        .await
        .map_err(|err| format!("Cannot write to tap {:?}", err))?;

    if size_written != packet.len() {
        return Err(format!("Tried to write packet of size {}, but only {} was written", packet.len(), size_written))
    }

    debug!("Sent data to tap!");

    Ok(())
}

fn receive_parent_network_settings(vsock : &mut VsockStream) -> Result<NetworkSettings, String> {
    let msg : SetupMessages = vsock.read_lv()?;

    match msg {
        SetupMessages::Settings(s) => { Ok(s) }
        x => {
            return Err(format!("Expected SetupMessages::Settings, but got {:?}", x))
        }
    }
}

async fn setup_enclave_networking(vsock : &mut VsockStream, parent_settings : &NetworkSettings) -> Result<AsyncDevice, String> {
    let tap_device = shared::device::create_async_tap_device(&parent_settings)?;

    debug!("Received next settings from parent {:?}", parent_settings);

    setup_enclave_networking0(&tap_device, &parent_settings).await?;

    info!("Finished network setup!");

    vsock.write_lv(&SetupMessages::SetupSuccessful)?;

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

    let gateway_addr = parent_settings.gateway_l2_address;
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

    netlink::add_neighbour(&netlink_handle, tap_index, gateway_addr, &parent_settings.gateway_l3_address).await?;
    info!("ARP entry is set!");

    Ok(())
}

#[cfg(feature = "sync")]
fn write_to_tap(tap_lock: &sync::Arc<sync::Mutex<Device>>, vsock: &mut VsockStream) -> Result<(), String> {
    let packet = vsock.read_lv_bytes()?;

    debug!("Received packet from parent! {:?}", packet);

    let mut tap_device = tap_lock.lock().map_err(|err| format!("Cannot acquire tap lock {:?}", err))?;

    debug!("acquired tap write lock!");

    match tap_device.write(&packet).map_err(|err| format!("Cannot write to tap {:?}", err)) {
        Ok(size_written) if size_written != packet.len() => {
            return Err(format!("Tried to write packet of size {}, but only {} was written", packet.len(), size_written))
        }
        Err(e) => {
            return Err(e)
        }
        _ => {}
    }

    debug!("Sent data to tap!");

    Ok(())
}

#[cfg(feature = "sync")]
fn read_from_tap(tap_lock: &sync::Arc<sync::Mutex<Device>>, vsock: &mut VsockStream, buf_len : u32) -> Result<usize, String> {
    let mut tap_device = tap_lock.lock().map_err(|err| format!("Cannot acquire tap lock {:?}", err))?;
    let mut buf = vec![0 as u8; buf_len as usize];

    debug!("acquired tap read lock!");

    let amount = match tap_device.read(&mut buf).map_err(|err| format!("Cannot read from tap {:?}", err)) {
        Ok(amount) => {
            amount
        }
        Err(_) => {
            return Ok(0)
        }
    };

    buf.truncate(amount);

    debug!("Read packet from tap! {:?}", buf);

    vsock.write_lv_bytes(&buf)?;

    debug!("Sent packet to parent!");

    Ok(1)
}

fn connect_to_parent(port : u32) -> Result<VsockStream, String> {
    let sockaddr = SockAddr::new_vsock(VSOCK_PARENT_CID, port);

    VsockStream::connect(&sockaddr).map_err(|err| format!("Failed to connect to enclave: {:?}", err))
}

async fn connect_to_parent_async(port : u32) -> Result<AsyncVsockStream, String> {
    AsyncVsockStream::connect(VSOCK_PARENT_CID, port)
        .await
        .map_err(|err| format!("Failed to connect to enclave: {:?}", err))
}
