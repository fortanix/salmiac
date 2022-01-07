use async_process::Command;
use log::{debug, info, error};
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
use shared::{VSOCK_PARENT_CID, DATA_SOCKET, PACKET_LOG_STEP, log_packet_processing, extract_enum_value, handle_background_task_exit, UserProgramExitStatus};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};

use std::net::IpAddr;
use std::path::{Path};
use std::fs;
use std::io::{Write};
use std::os::unix::io::{AsRawFd};
use std::time::Duration;
use std::thread;
use std::mem;
use mbedtls::x509::Certificate;
use std::sync::Arc;
use em_app::CsrSigner;


const ENTROPY_BYTES_COUNT : usize = 126;
const ENTROPY_REFRESH_PERIOD : u64 = 30;

pub async fn run(vsock_port: u32, settings_path : &Path) -> Result<UserProgramExitStatus, String> {
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

    let (tap_read, tap_write) = io::split(async_tap_device.tap_device);
    let (vsock_read, vsock_write) = io::split(parent_data_port);

    let mtu = parent_settings.mtu;

    let read_tap_loop = tokio::spawn(read_from_tap_async(tap_read, vsock_write, mtu));

    debug!("Started tap read loop!");

    let write_tap_loop = tokio::spawn(write_to_tap_async(tap_write, vsock_read));

    debug!("Started tap write loop!");

    let user_program = tokio::spawn(start_user_program(enclave_settings, parent_port));

    debug!("Started client program!");

    if let (Some(certificate), Some(key)) = (async_tap_device.certificate, async_tap_device.key) {
        setup_corvin(certificate, key)?;
        return Err("FINSIHED CORVIN".to_string())
    }

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
        result = user_program => {
            result.map_err(|err| format!("Join error in user program wait loop. {:?}", err))?
        },
    }
}

fn setup_corvin(mut certificate : String, mut key : Pk) -> Result<(), String> {
    info!("Setting up Corvin configuration");

    certificate.push('\0');

    let app_cert = Certificate::from_pem_multiple(&certificate.as_bytes())
        .map_err(|e| format!("Parsing certificate failed: {:?}", e))?;

    info!("Requesting application config");

    let app_config = em_app::utils::get_runtime_configuration(
        "test.otilia.dev",
        9090,
        Arc::new(app_cert),
        Arc::new(key),
        None,
        None).map_err(|e| format!("Failed retrieving application configuration: {:?}", e))?;

    error!("APP CONF IS {:?}", app_config);

    Ok(())
}

async fn start_user_program(enclave_settings : EnclaveSettings, mut vsock : AsyncVsockStream) -> Result<UserProgramExitStatus, String> {
    let mut client_command = Command::new(enclave_settings.user_program_config.entry_point.clone());

    if !enclave_settings.user_program_config.arguments.is_empty() {
        client_command.args(enclave_settings.user_program_config.arguments.clone());
    }

    let client_program = client_command.spawn()
        .map_err(|err| format!("Failed to start client program!. {:?}", err))?;

    let output = client_program.output()
        .await
        .map_err(|err| format!("Error while waiting for client program to finish: {:?}", err))?;

    let result = if let Some(code) = output.status.code() {
        UserProgramExitStatus::ExitCode(code)
    } else {
        UserProgramExitStatus::TerminatedBySignal
    };

    vsock.write_lv(&SetupMessages::UserProgramExit(result.clone())).await?;

    Ok(result)
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

async fn setup_enclave(vsock : &mut AsyncVsockStream, parent_settings : &NetworkSettings, cert_settings : &Vec<CertificateConfig>) -> Result<EnclaveSetupResult, String> {
    let tap_device = setup_enclave_networking(&parent_settings).await?;

    info!("Finished enclave network setup!");

    let app_config_id_msg: SetupMessages = vsock.read_lv().await?;
    let app_config_id = extract_enum_value!(app_config_id_msg, SetupMessages::ApplicationConfigId(e) => e)?;

    let mut num_certs : u64 = 0;

    let mut certificate : Option<String> = None;
    let mut key : Option<Pk> = None;

    // Zero or more certificate requests.
    for cert in cert_settings {
        let (cert, k) = setup_enclave_certification(vsock, &app_config_id, &cert).await?;
        certificate = Some(cert);
        key = Some(k);

        num_certs += 1;
    }

    info!("Finished requesting {} certificates.", num_certs);

    vsock.write_lv(&SetupMessages::SetupSuccessful).await?;
    info!("Notified parent that setup was successful");

    Ok(EnclaveSetupResult {
        tap_device,
        certificate,
        key
    })
}

struct EnclaveSetupResult {
    tap_device : AsyncDevice,

    certificate : Option<String>,

    key : Option<Pk>
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

    fs::create_dir("/run/resolvconf")
        .map_err(|err| format!("Failed creating /run/resolvconf. {:?}", err))?;

    let mut dns_file = fs::File::create("/run/resolvconf/resolv.conf")
        .map_err(|err| format!("Failed to create enclave /run/resolvconf/resolv.conf. {:?}", err))?;

    dns_file.write_all(&parent_settings.dns_file)
        .map_err(|err| format!("Failed writing to /run/resolvconf/resolv.conf. {:?}", err))?;

    info!("Enclave DNS file has been populated!");

    Ok(tap_device)
}

async fn setup_enclave_certification(vsock : &mut AsyncVsockStream, app_config_id: &Option<String>,
                                     cert_settings : &CertificateConfig) -> Result<(String, Pk), String> {
    let mut rng = Rdrand;
    let mut key = Pk::generate_rsa(&mut rng, 3072, 0x10001)
        .map_err(|err| format!("Failed to generate RSA key. {:?}", err))?;

    let common_name = cert_settings.subject
        .as_ref()
        .map(|e| e.as_str())
        .unwrap_or("localhost");
    info!("APPID IS {:?}", app_config_id);
    let csr = em_app::get_remote_attestation_csr(
        "localhost", //this param is not used for now
        common_name,
        &mut key,
        None,
        app_config_id.as_deref())
        .map_err(|err| format!("Failed to get CSR. {:?}", err))?;

    vsock.write_lv(&SetupMessages::CSR(csr)).await?;

    let certificate_msg: SetupMessages = vsock.read_lv().await?;

    let certificate = extract_enum_value!(certificate_msg, SetupMessages::Certificate(s) => s)?;

    info!("CERTIFICATE IS {}", certificate);

    let key_as_pem = key.write_private_pem_string()
        .map_err(|err| format!("Failed to write key as PEM format. {:?}", err))?;

    let key_path = cert_settings.key_path
        .as_ref()
        .map(|e| e.as_str())
        .unwrap_or("key");

    let certificate_path = cert_settings.cert_path
        .as_ref()
        .map(|e| e.as_str())
        .unwrap_or("cert");

    create_key_file(Path::new(key_path), &key_as_pem)?;
    create_key_file(Path::new(certificate_path), &certificate)?;

    Ok((certificate, key))
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

fn seed_entropy(entropy_bytes_count: usize, nsm_device : &NSMDevice, random_device : &mut fs::File) -> Result<(), String> {
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
