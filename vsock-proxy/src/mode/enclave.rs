use crate::net::netlink;
use crate::net::device::{NetworkSettings, SetupMessages};
use crate::net::socket::{RichSocket};
use crate::{net};
use crate::mode::VSOCK_PARENT_CID;

use tun::platform::linux::Device;
use log::{
    debug,
    info,
    error
};
use nix::net::if_::if_nametoindex;
use vsock::VsockStream;
use threadpool::ThreadPool;
use nix::sys::socket::SockAddr;

use std::net::IpAddr;
use std::{sync, thread};
use std::io::{Write, Read};

pub fn run(vsock_port: u32) -> Result<(), String> {
    let thread_pool = ThreadPool::new(2);
    let mut parent_connection = connect_to_parent(vsock_port)?;

    info!("Connected to parent!");

    let parent_settings = receive_parent_network_settings(&mut parent_connection)?;
    let tap_device = setup_enclave_networking(&mut parent_connection, &parent_settings)?;
    debug!("Created tap device in enclave!");

    let sync_tap = sync::Arc::new(sync::Mutex::new(tap_device));

    let tap_write = sync_tap.clone();
    let tap_read = sync_tap.clone();

    let mut vsock_write = parent_connection.clone();
    let mut vsock_read = parent_connection.clone();

    let mtu = parent_settings.mtu;
    thread_pool.execute(move || {
        loop {
            let read = read_from_tap(&tap_read, &mut vsock_write, mtu);

            match read {
                Ok(0) => {
                    thread::sleep_ms(5000); // if nothing was read then wait some time for packet
                }
                // FIXME: SALM-35
                Err(e) => {
                    error!("Failure reading from tap device {:?}", e);
                    break;
                }
                _ => { }
            }
        }
    });

    thread_pool.execute(move || {
        loop {
            match write_to_tap(&tap_write, &mut vsock_read) {
                Err(e) => {
                    error!("Failure reading from tap device {:?}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    thread_pool.join();

    Ok(())
}

fn receive_parent_network_settings(vsock : &mut VsockStream) -> Result<NetworkSettings, String> {
    let msg : SetupMessages = vsock.receive()?;

    match msg {
        SetupMessages::Settings(s) => { Ok(s) }
        x => {
            return Err(format!("Expected SetupMessages::Settings, but got {:?}", x))
        }
    }
}

fn setup_enclave_networking(vsock : &mut VsockStream, parent_settings : &NetworkSettings) -> Result<Device, String> {
    let tap_device = net::device::create_tap_device(&parent_settings)?;
    tap_device.set_nonblock().map_err(|_err| "Cannot set nonblock for tap device".to_string())?;

    debug!("Received next settings from parent {:?}", parent_settings);

    setup_enclave_networking0(&tap_device, &parent_settings)?;

    info!("Finished network setup!");

    vsock.send(SetupMessages::SetupSuccessful)?;

    Ok(tap_device)
}

#[tokio::main]
async fn setup_enclave_networking0(tap_device : &Device, parent_settings : &NetworkSettings) -> Result<(), String> {
    use tun::Device;

    let (_netlink_connection, netlink_handle) = netlink::connect();
    tokio::spawn(_netlink_connection);

    debug!("Connected to netlink");

    let tap_index = if_nametoindex(tap_device.name()).map_err(|err| format!("Cannot find index for tap device {:?}", err))?;

    debug!("Tap index {}", tap_index);

    netlink::set_address(&netlink_handle, tap_index, &parent_settings.self_l2_address).await?;
    info!("MAC address for tap is set!");

    let gateway_addr = parent_settings.gateway_l2_address;
    let as_ipv4 = match gateway_addr.clone() {
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

fn write_to_tap(tap_lock: &sync::Arc<sync::Mutex<Device>>, vsock: &mut VsockStream) -> Result<(), String> {
    let packet : Vec<u8> = vsock.receive()?;

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

    let packet = &buf[0..amount];

    debug!("Read packet from tap! {:?}", packet);

    vsock.send(packet.to_vec())?;

    debug!("Sent packet to parent!");

    Ok(1)
}

fn connect_to_parent(port : u32) -> Result<VsockStream, String> {
    let sockaddr = SockAddr::new_vsock(VSOCK_PARENT_CID, port);

    VsockStream::connect(&sockaddr).map_err(|err| format!("Failed to connect to enclave: {:?}", err))
}