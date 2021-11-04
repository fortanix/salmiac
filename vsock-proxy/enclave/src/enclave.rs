use log::{debug, info};
use nix::net::if_::if_nametoindex;
use nix::ioctl_write_ptr;
use tokio_vsock::VsockStream as AsyncVsockStream;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tun::AsyncDevice;
use mbedtls::pk::Pk;
use mbedtls::rng::Rdrand;
use api_model::CertificateConfig;
use api_model::shared::EnclaveSettings;

use shared::device::{NetworkSettings, SetupMessages};
use shared::{VSOCK_PARENT_CID, DATA_SOCKET, PACKET_LOG_STEP, log_packet_processing, extract_enum_value};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};

use std::net::IpAddr;
use std::path::{Path};
use std::fs;
use std::io::{Write};
use std::os::unix::io::{AsRawFd};
use std::time::Duration;
use std::thread;
use std::fs::File;
use std::mem;
use std::process::Command;
use tokio::task::JoinError;

const ENTROPY_BYTES_COUNT : usize = 126;
const ENTROPY_REFRESH_PERIOD : u64 = 30;

pub async fn run(vsock_port: u32, settings_path : &Path) -> Result<i32, String> {
    let enclave_settings = read_enclave_settings(settings_path)?;

    debug!("Received enclave settings {:?}", enclave_settings);

    let mut parent_port = connect_to_parent_async(vsock_port).await?;

    info!("Connected to parent!");

    let parent_data_port = connect_to_parent_async(DATA_SOCKET).await?;

    info!("Connected to parent to transmit data!");

    let msg : SetupMessages = parent_port.read_lv().await?;

    let parent_settings = extract_enum_value!(msg, SetupMessages::Settings(s) => s)?;

    let async_tap_device = setup_enclave(&mut parent_port, &parent_settings, &enclave_settings.certificate_config).await?;

    let entropy_loop = tokio::task::spawn_blocking(|| {
        start_entropy_seeding_loop(ENTROPY_BYTES_COUNT, ENTROPY_REFRESH_PERIOD)
    });

    let (tap_read, tap_write) = io::split(async_tap_device);
    let (vsock_read, vsock_write) = io::split(parent_data_port);

    let mtu = parent_settings.mtu;

    let read_tap_loop = tokio::spawn(read_from_tap_async(tap_read, vsock_write, mtu));

    debug!("Started tap read loop!");

    let write_tap_loop = tokio::spawn(write_to_tap_async(tap_write, vsock_read));

    debug!("Started tap write loop!");

    let client_program = tokio::task::spawn_blocking(move || {
        start_client_program(&enclave_settings)
    });

    debug!("Started client program!");

    // We wait for the first future to complete.
    // Loop futures will never complete with success because they run forever
    // and if the client program finishes then we are done.
    tokio::select! {
        result = read_tap_loop => {
            handle_background_task_exit(result, "tap read loop")
        },
        result = write_tap_loop => {
            handle_background_task_exit(result, "tap write loop")
        },
        result = entropy_loop => {
            handle_background_task_exit(result, "entropy seed loop")
        },
        result = client_program => {
            result.map_err(|err| format!("Join error in client program wait loop. {:?}", err))?
        },
    }
}

fn handle_background_task_exit(result : Result<Result<(), String>, JoinError>, task_name : &str) -> Result<i32, String> {
    match result {
        Err(err) => {
            Err(format!("Join error in {}. {:?}", task_name, err))?
        }
        Ok(Err(err)) => {
            Err(err)
        }
        // Background tasks never exit with success
        _ => { unreachable!() }
    }
}

fn start_client_program(enclave_settings : &EnclaveSettings) -> Result<i32, String> {
    let mut client_command = Command::new(enclave_settings.client_cmd.clone());

    if !enclave_settings.client_cmd_args.is_empty() {
        client_command.args(enclave_settings.client_cmd_args.clone());
    }

    let client_program = client_command.spawn()
        .map_err(|err| format!("Failed to start client program!. {:?}", err))?;

    match client_program.wait_with_output() {
        Ok(output) if output.status.code().is_some() => {
            let status = output.status.code().unwrap();

            Ok(status)
        }
        Ok(_) => {
            Err(format!("Client program terminated by signal."))
        }
        Err(err) => {
            Err(format!("Error while waiting for client program to finish: {:?}", err))
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

async fn setup_enclave(vsock : &mut AsyncVsockStream, parent_settings : &NetworkSettings, enclave_settings : &CertificateConfig) -> Result<AsyncDevice, String> {
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

async fn setup_enclave_certification(vsock : &mut AsyncVsockStream, settings : &CertificateConfig) -> Result<(), String> {
    let mut rng = Rdrand;
    let mut key = Pk::generate_rsa(&mut rng, 3072, 0x10001)
        .map_err(|err| format!("Failed to generate RSA key. {:?}", err))?;

    let common_name = settings.subject
        .as_ref()
        .map(|e| e.as_str())
        .unwrap_or("localhost");

    let csr = em_app::get_remote_attestation_csr(
        "localhost", //this param is not used for now
        common_name,
        &mut key,
        None,
        None)
        .map_err(|err| format!("Failed to get CSR. {:?}", err))?;

    vsock.write_lv(&SetupMessages::CSR(csr)).await?;

    let certificate_msg: SetupMessages = vsock.read_lv().await?;

    let certificate = extract_enum_value!(certificate_msg, SetupMessages::Certificate(s) => s)?;

    let key_as_pem = key.write_private_pem_string()
        .map_err(|err| format!("Failed to write key as PEM format. {:?}", err))?;

    let key_path = settings.key_path
        .as_ref()
        .map(|e| e.as_str())
        .unwrap_or("key");

    let certificate_path = settings.cert_path
        .as_ref()
        .map(|e| e.as_str())
        .unwrap_or("cert");

    create_key_file(Path::new(key_path), &key_as_pem)?;
    create_key_file(Path::new(certificate_path), &certificate)
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

fn read_enclave_settings(path : &Path) -> Result<EnclaveSettings, String> {
    let settings_raw = fs::read_to_string(path)
        .map_err(|err| format!("Failed to read enclave settings file. {:?}", err))?;

    serde_json::from_str(&settings_raw)
        .map_err(|err| format!("Failed to deserialize enclave settings. {:?}", err))
}


// Linux ioctl #define RNDADDTOENTCNT	_IOW( 'R', 0x01, int )
ioctl_write_ptr!(set_entropy, 'R' as u8, 0x01, u32);

const GET_RANDOM_MAX_OUTPUT : usize = 256;

// This is a workaround for indefinite blocking when someone tries to read from /dev/random device.
// The reason for blocking is that as of now the enclave doesn’t provide any entropy for the random device
// and linux can’t return any random number for the caller and blocks indefinitely.
// The workaround will be removed when NSM is able to seed the entropy automatically as described here:
// https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/pull/9
fn start_entropy_seeding_loop(entropy_bytes_count: usize, refresh_period: u64) -> Result<(), String> {
    let nsm_device = NSMDevice::new()?;

    let mut random_device = fs::OpenOptions::new()
        .write(true)
        .open("/dev/random")
        .map_err(|err| format!("Failed to open /dev/random. {:?}", err))?;

    let result = thread::spawn(move || -> Result<(), String> {
        loop {
            seed_entropy(entropy_bytes_count, &nsm_device, &mut random_device)?;

            debug!("Successfully seeded entropy with {} bytes", entropy_bytes_count);

            thread::sleep(Duration::new(refresh_period, 0))
        }
    });

    result.join()
        .map_err(|err| format!("Failure in entropy seeding loop. {:?}", err))?
}

fn seed_entropy(entropy_bytes_count: usize, nsm_device : &NSMDevice, random_device : &mut File) -> Result<(), String> {
    let mut count = 0 as usize;

    while count != entropy_bytes_count {
        let mut buf = [0 as u8; GET_RANDOM_MAX_OUTPUT];

        let array_size = mem::size_of::<[u8; GET_RANDOM_MAX_OUTPUT]>();
        let mut buf_len = if array_size > (entropy_bytes_count - count) {
            entropy_bytes_count - count
        } else {
            array_size
        };

        match unsafe { nsm::nsm_get_random(nsm_device.descriptor, buf.as_mut_ptr(), &mut buf_len) } {
            nsm_io::ErrorCode::Success => {},
            err => {
                return Err(format!("Failed to get random from nsm. {:?}", err))
            }
        }

        if buf_len == 0 {
            return Err(format!("Nsm returned 0 entropy"))
        }

        // write new entropy seed into /dev/random
        random_device.write_all(&mut buf)
            .map_err(|err| format!("Failed to write entropy to /dev/random. {:?}", err))?;

        let entropy_bits = (buf_len * 8) as u32;

        // Now we can increment entropy count of the entropy pool
        // by calling a proper ioctl on /dev/random as described here:
        // https://man7.org/linux/man-pages/man4/random.4.html
        match unsafe { set_entropy(random_device.as_raw_fd(), &entropy_bits) } {
            Ok(result_code) if result_code < 0 => {
                return Err(format!("Ioctl exited with code: {}", result_code))
            },
            Err(err) => {
                return Err(format!("Ioctl exited with error: {:?}", err))
            },
            _ => {}
        }
        count += buf_len;
    }

    Ok(())
}

// Wraps NSM descriptor to implement Drop
struct NSMDevice {
    descriptor : i32
}

impl NSMDevice {
    fn new() -> Result<Self, String> {
        let descriptor = nsm::nsm_lib_init();

        if descriptor < 0 {
            return Err(format!("Failed initializing nsm lib. Returned {}", descriptor))
        }

        Ok(NSMDevice {
            descriptor
        })
    }
}

impl Drop for NSMDevice {
    fn drop(&mut self) {
        nsm::nsm_lib_exit(self.descriptor);
    }
}
