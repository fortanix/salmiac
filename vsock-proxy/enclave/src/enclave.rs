use log::{debug, info};
use nix::net::if_::if_nametoindex;
use tokio_vsock::VsockStream as AsyncVsockStream;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tun::AsyncDevice;
use serde::{Serialize, Deserialize};
use mbedtls::pk::Pk;
use mbedtls::rng::Rdrand;

use shared::device::{NetworkSettings, SetupMessages};
use shared::{VSOCK_PARENT_CID, DATA_SOCKET, PACKET_LOG_STEP, log_packet_processing, extract_enum_value};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};

use std::net::IpAddr;
use std::path::{Path};
use std::fs;
use std::io::Write;

pub async fn run(vsock_port: u32, settings_path : &Path) -> Result<(), String> {
    let enclave_settings = read_enclave_settings(settings_path)?;

    debug!("Received enclave settings {:?}", enclave_settings);

    let mut parent_port = connect_to_parent_async(vsock_port).await?;

    info!("Connected to parent!");

    let parent_data_port = connect_to_parent_async(DATA_SOCKET).await?;

    info!("Connected to parent to transmit data!");

    let msg : SetupMessages = parent_port.read_lv().await?;

    let parent_settings = extract_enum_value!(msg, SetupMessages::Settings(s) => s)?;

    let async_tap_device = setup_enclave(&mut parent_port, &parent_settings, &enclave_settings).await?;

    let (tap_read, tap_write) = io::split(async_tap_device);
    let (vsock_read, vsock_write) = io::split(parent_data_port);

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

async fn setup_enclave(vsock : &mut AsyncVsockStream, parent_settings : &NetworkSettings, enclave_settings : &Settings) -> Result<AsyncDevice, String> {
    let async_tap_device = setup_enclave_networking(&parent_settings).await?;

    info!("Finished enclave network setup!");

    setup_enclave_certification(vsock, &enclave_settings).await?;

    info!("Finished enclave attestation!");

    vsock.write_lv(&SetupMessages::SetupSuccessful).await?;

    Ok(async_tap_device)
}

async fn setup_enclave_networking(parent_settings : &NetworkSettings) -> Result<AsyncDevice, String> {
    use shared::netlink;
    use tun::Device;

    let tap_device = shared::device::create_async_tap_device(&parent_settings)?;

    debug!("Received network settings from parent {:?}", parent_settings);

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

    Ok(tap_device)
}

async fn setup_enclave_certification(vsock : &mut AsyncVsockStream, settings : &Settings) -> Result<(), String> {
    let mut rng = Rdrand;
    let mut key = Pk::generate_rsa(&mut rng, 3072, 0x10001).unwrap();

    let csr = em_app::get_remote_attestation_csr(
        &settings.key_url,
        &settings.key_domain,
        &mut key,
        None,
        None)
        .map_err(|err| format!("Failed to get CSR. {:?}", err))?;

    debug!("Sending CSR {} to parent!", csr);

    vsock.write_lv(&SetupMessages::CSR(csr)).await?;

    let certificate_msg: SetupMessages = vsock.read_lv().await?;

    let certificate = extract_enum_value!(certificate_msg, SetupMessages::Certificate(s) => s)?;

    let key_as_pem = key.write_private_pem_string()
        .map_err(|err| format!("Failed to write key as PEM format. {:?}", err))?;

    create_key_file(Path::new(&settings.key_path), &key_as_pem)?;
    create_key_file(Path::new(&settings.certificate_path), &certificate)
}

async fn connect_to_parent_async(port : u32) -> Result<AsyncVsockStream, String> {
    AsyncVsockStream::connect(VSOCK_PARENT_CID, port)
        .await
        .map_err(|err| format!("Failed to connect to parent: {:?}", err))
}

fn create_key_file(path : &Path, key : &str) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(path)
        .map_err(|err| format!("Failed to create key file {}. {:?}", path.display(), err))?;

    file.write_all(key.as_bytes())
        .map_err(|err| format!("Failed to write data into key file {}. {:?}", path.display(), err))
}

fn read_enclave_settings(path : &Path) -> Result<Settings, String> {
    let settings_raw = fs::read_to_string(path)
        .map_err(|err| format!("Failed to read enclave settings file. {:?}", err))?;

    serde_json::from_str(&settings_raw)
        .map_err(|err| format!("Failed to deserialize enclave settings. {:?}", err))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Settings {
    pub key_url : String,

    pub key_domain : String,

    pub key_path : String,

    pub certificate_path : String
}
