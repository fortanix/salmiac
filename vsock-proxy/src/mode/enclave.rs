use crate::net::netlink;
use crate::net::device::{NetworkSettings, SetupMessages};
use crate::net::socket::{RichSocket};

use tun::platform::linux::Device;
use log::{
    debug,
    info,
    error
};

use std::net::IpAddr;
use crate::{net, Proxy};
use vsock::VsockStream;
use threadpool::ThreadPool;
use std::{sync, thread};
use std::io::{Write, Read};

pub fn run(local_port : u32, remote_port : u16, thread_pool : ThreadPool) -> Result<(), String> {
    debug!("Created tap device in enclave!");

    let server = Proxy::new(local_port, 4, remote_port);

    let mut parent_connection = server.connect_to_parent()?;

    info!("Connected to parent!");

    let tap_device = communicate_network_settings(&mut parent_connection)?;

    let sync_tap = sync::Arc::new(sync::Mutex::new(tap_device));

    let tap_write = sync_tap.clone();
    let tap_read = sync_tap.clone();

    let mut vsock_write = parent_connection.clone();
    let mut vsock_read = parent_connection.clone();

    thread_pool.execute(move || {
        loop {
            let read = read_from_tap(&tap_read, &mut vsock_write);

            match read {
                Ok(0) => {
                    thread::sleep_ms(5000); // if nothing was read then wait some time for packet
                }
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

fn communicate_network_settings(vsock : &mut VsockStream) -> Result<Device, String> {
    let msg : SetupMessages = vsock.receive()?;

    let parent_settings = match msg {
        SetupMessages::Settings(s) => { s }
        x => {
            panic!("Expected SetupMessages::Settings, but got {:?}", x)
        }
    };

    let tap_device = net::device::create_tap_device(&parent_settings)?;
    tap_device.set_nonblock().map_err(|_err| "Cannot set nonblock for tap device".to_string())?;

    debug!("Received next settings from parent {:?}", parent_settings);

    setup_enclave_networking(&tap_device, &parent_settings)?;

    info!("Finished network setup!");

    vsock.send(SetupMessages::SetupSuccessful)?;

    Ok(tap_device)
}

#[tokio::main]
async fn setup_enclave_networking(tap_device : &Device, parent_settings : &NetworkSettings) -> Result<(), String> {
    use tun::Device;
    use nix::net::if_::if_nametoindex;

    let (_netlink_connection, netlink_handle) = netlink::connect();
    tokio::spawn(_netlink_connection);

    debug!("Connected to netlink");

    let tap_index = if_nametoindex(tap_device.name()).map_err(|err| format!("Cannot find index for tap device {:?}", err))?;

    debug!("Tap index {}", tap_index);

    netlink::set_address(&netlink_handle, tap_index, parent_settings.mac_address.to_vec()).await?;
    info!("MAC address for tap is set!");

    let gateway_addr = parent_settings.gateway_address;
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

    netlink::add_neighbour(&netlink_handle, tap_index, gateway_addr, parent_settings.link_local_address.to_vec()).await?;
    info!("ARP entry is set!");

    Ok(())
}

fn write_to_tap(tap_lock: &sync::Arc<sync::Mutex<Device>>, from_parent: &mut VsockStream) -> Result<(), String> {
    let packet : Vec<u8> = from_parent.receive()?;

    debug!("Received packet from parent! {:?}", packet);

    let mut tap_device = tap_lock.lock().map_err(|err| format!("Cannot acquire tap lock {:?}", err))?;

    debug!("acquired tap write lock!");

    tap_device.write_all(&packet).map_err(|err| format!("Cannot write to tap {:?}", err))?;

    debug!("Sent data to tap!");

    Ok(())
}

fn read_from_tap(tap_lock: &sync::Arc<sync::Mutex<Device>>, parent_connection: &mut VsockStream) -> Result<usize, String> {
    let mut buf = [0u8; 4096];

    let mut tap_device = tap_lock.lock().map_err(|err| format!("Cannot acquire tap lock {:?}", err))?;

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

    parent_connection.send(packet.to_vec())?;

    debug!("Sent packet to parent!");

    Ok(1)
}