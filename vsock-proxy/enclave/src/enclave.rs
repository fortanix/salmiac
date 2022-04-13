use async_process::Command;
use futures::StreamExt;
use log::{debug, info};
use nix::ioctl_write_ptr;
use nix::net::if_::if_nametoindex;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tokio_vsock::VsockStream as AsyncVsockStream;
use tun::AsyncDevice;
use tun::Device;

use crate::app_configuration::{setup_application_configuration, EmAppApplicationConfiguration};
use crate::certificate::{request_certificate, write_certificate_info_to_file_system, CertificateResult};
use api_model::shared::EnclaveSettings;
use api_model::CertificateConfig;
use shared::device::{NetworkDeviceSettings, SetupMessages};
use shared::netlink::arp::NetlinkARP;
use shared::netlink::route::NetlinkRoute;
use shared::netlink::{Netlink, NetlinkCommon};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use shared::{
    extract_enum_value, handle_background_task_exit, log_packet_processing, UserProgramExitStatus, MAX_ETHERNET_HEADER_SIZE,
    PACKET_LOG_STEP, VSOCK_PARENT_CID,
};

use futures::stream::FuturesUnordered;
use std::fs;
use std::io::Write;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::thread;
use std::time::Duration;

const ENTROPY_BYTES_COUNT: usize = 126;
const ENTROPY_REFRESH_PERIOD: u64 = 30;

pub async fn run(vsock_port: u32, settings_path: &Path) -> Result<UserProgramExitStatus, String> {
    let enclave_settings = read_enclave_settings(settings_path)?;

    debug!("Received enclave settings {:?}", enclave_settings);

    let mut parent_port = connect_to_parent_async(vsock_port).await?;

    info!("Connected to parent!");

    let app_config = extract_enum_value!(parent_port.read_lv().await?, SetupMessages::ApplicationConfig(e) => e)?;

    let setup_result = setup_enclave(&mut parent_port, &enclave_settings.certificate_config, &app_config.id).await?;

    let entropy_loop = tokio::task::spawn_blocking(|| start_entropy_seeding_loop(ENTROPY_BYTES_COUNT, ENTROPY_REFRESH_PERIOD));

    let mut background_tasks = FuturesUnordered::new();

    for tap_device in setup_result.tap_devices {
        let (read_tap_loop, write_tap_loop) = start_tap_loops(tap_device.tap, tap_device.vsock, tap_device.mtu);

        background_tasks.push(read_tap_loop);
        background_tasks.push(write_tap_loop);
    }

    // We can request application configuration only if we know application id.
    // Also we can run configuration retrieval function only after we start our tap loops,
    // because the function makes a network request
    if let (Some(certificate_info), Some(_)) = (setup_result.certificate_info, app_config.id) {
        let api = Box::new(EmAppApplicationConfiguration::new());
        setup_application_configuration(
            certificate_info,
            &app_config.ccm_backend_url,
            app_config.skip_server_verify,
            api,
        )?;
    }

    let user_program = tokio::spawn(start_user_program(enclave_settings, parent_port));

    debug!("Started client program!");

    // We wait for the first future to complete.
    // Loop futures will never complete with success because they run forever
    // and if the client program finishes then we are done.
    tokio::select! {
        result = background_tasks.next() => {
            handle_background_task_exit(result, "tap loop")
        },
        result = entropy_loop => {
            handle_background_task_exit(Some(result), "entropy seed loop")
        },
        result = user_program => {
            result.map_err(|err| format!("Join error in user program wait loop. {:?}", err))?
        },
    }
}

fn start_tap_loops(
    tap_device: AsyncDevice,
    vsock: AsyncVsockStream,
    mtu: u32,
) -> (JoinHandle<Result<(), String>>, JoinHandle<Result<(), String>>) {
    let (tap_read, tap_write) = io::split(tap_device);
    let (vsock_read, vsock_write) = io::split(vsock);

    let read_tap_loop = tokio::spawn(read_from_tap_async(tap_read, vsock_write, mtu));

    let write_tap_loop = tokio::spawn(write_to_tap_async(tap_write, vsock_read));

    (read_tap_loop, write_tap_loop)
}

async fn start_user_program(
    enclave_settings: EnclaveSettings,
    mut vsock: AsyncVsockStream,
) -> Result<UserProgramExitStatus, String> {
    let mut client_command = Command::new(enclave_settings.user_program_config.entry_point.clone());

    if !enclave_settings.user_program_config.arguments.is_empty() {
        client_command.args(enclave_settings.user_program_config.arguments.clone());
    }

    let client_program = client_command
        .spawn()
        .map_err(|err| format!("Failed to start client program!. {:?}", err))?;

    let output = client_program
        .output()
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

async fn setup_enclave(
    vsock: &mut AsyncVsockStream,
    cert_configs: &Vec<CertificateConfig>,
    application_id: &Option<String>,
) -> Result<EnclaveSetupResult, String> {
    let taps = setup_enclave_networking(vsock).await?;

    info!("Finished enclave networking setup!");

    let certificate_info = setup_enclave_certification(vsock, application_id, &cert_configs).await?;

    vsock.write_lv(&SetupMessages::SetupSuccessful).await?;
    info!("Notified parent that setup was successful");

    Ok(EnclaveSetupResult {
        tap_devices: taps,
        certificate_info,
    })
}

struct EnclaveSetupResult {
    tap_devices: Vec<TapDeviceInfo>,

    certificate_info: Option<CertificateResult>,
}

struct TapDeviceInfo {
    pub vsock: AsyncVsockStream,

    pub tap: AsyncDevice,

    pub mtu: u32,
}

async fn setup_enclave_networking(parent_port: &mut AsyncVsockStream) -> Result<Vec<TapDeviceInfo>, String> {
    let netlink = Netlink::new();

    let device_settings_list = extract_enum_value!(parent_port.read_lv().await?, SetupMessages::NetworkDeviceSettings(s) => s)?;

    let mut result: Vec<TapDeviceInfo> = Vec::new();

    for device_settings in &device_settings_list {
        let tap = setup_network_device(device_settings, &netlink).await?;
        let vsock = connect_to_parent_async(device_settings.index).await?;

        info!("Device {} is connected and ready!", device_settings.index);

        result.push(TapDeviceInfo {
            vsock,
            tap,
            mtu: device_settings.mtu,
        });
    }

    let global_settings = extract_enum_value!(parent_port.read_lv().await?, SetupMessages::GlobalNetworkSettings(s) => s)?;

    fs::create_dir("/run/resolvconf").map_err(|err| format!("Failed creating /run/resolvconf. {:?}", err))?;

    let mut dns_file = fs::File::create("/run/resolvconf/resolv.conf")
        .map_err(|err| format!("Failed to create enclave /run/resolvconf/resolv.conf. {:?}", err))?;

    dns_file
        .write_all(&global_settings.dns_file)
        .map_err(|err| format!("Failed writing to /run/resolvconf/resolv.conf. {:?}", err))?;

    info!("Enclave DNS file has been populated!");

    Ok(result)
}

async fn setup_network_device(parent_settings: &NetworkDeviceSettings, netlink: &Netlink) -> Result<AsyncDevice, String> {
    let tap_device = shared::device::create_async_tap_device(&parent_settings)?;

    let tap_index =
        if_nametoindex(tap_device.get_ref().name()).map_err(|err| format!("Cannot find index for tap device {:?}", err))?;

    info!(
        "Setting up device with index {} and settings {:?}.",
        tap_index, parent_settings
    );

    netlink
        .set_link_for_device(tap_index, &parent_settings.self_l2_address)
        .await?;
    debug!("MAC address for tap is set!");

    // It is required that we add routes first and than the gateway
    // Kernel allows us to add the gateway only if there is a reachable route for gateway's address in the routing table.
    // Without said the route(s) the kernel will return NETWORK_UNREACHABLE status code for our add_gateway function.
    for route in &parent_settings.routes {
        match netlink.add_route_for_device(tap_index, route).await {
            Err(e) => {
                log::warn!("Failed adding route {:?}", e);
            }
            _ => {
                info!("Added route {:?}!", route);
            }
        }
    }

    if let Some(gateway) = &parent_settings.gateway {
        netlink.add_gateway(gateway).await?;
        debug!("Gateway {:?} is set!", parent_settings.gateway);
    }

    // It might be the case when parent's neighbour resolution depends on a static manually inserted ARP entries
    // and not on protocol's capability to automatically learn neighbours. In this case we have to manually copy
    // those entries from parent as it becomes the only way for the enclave to know it's neighbours.
    for arp_entry in &parent_settings.static_arp_entries {
        netlink.add_neighbour_for_device(tap_index, arp_entry).await?;

        debug!("ARP entry {:?} is set!", arp_entry);
    }

    Ok(tap_device)
}

async fn setup_enclave_certification(
    vsock: &mut AsyncVsockStream,
    app_config_id: &Option<String>,
    cert_settings: &Vec<CertificateConfig>,
) -> Result<Option<CertificateResult>, String> {
    let mut num_certs: u64 = 0;
    let mut first_certificate: Option<CertificateResult> = None;

    // Zero or more certificate requests.
    for cert in cert_settings {
        let mut certificate_result = request_certificate(vsock, cert, app_config_id).await?;

        let key_as_pem = certificate_result
            .key
            .write_private_pem_string()
            .map_err(|err| format!("Failed to write key as PEM format. {:?}", err))?;

        write_certificate_info_to_file_system(&key_as_pem, &certificate_result.certificate, cert)?;

        if let None = first_certificate {
            first_certificate = Some(certificate_result);
        }

        num_certs += 1;
    }

    info!("Finished requesting {} certificates.", num_certs);

    Ok(first_certificate)
}

async fn connect_to_parent_async(port: u32) -> Result<AsyncVsockStream, String> {
    AsyncVsockStream::connect(VSOCK_PARENT_CID, port)
        .await
        .map_err(|err| format!("Failed to connect to parent: {:?}", err))
}

fn read_enclave_settings(path: &Path) -> Result<EnclaveSettings, String> {
    let settings_raw = fs::read_to_string(path).map_err(|err| format!("Failed to read enclave settings file. {:?}", err))?;

    serde_json::from_str(&settings_raw).map_err(|err| format!("Failed to deserialize enclave settings. {:?}", err))
}

// Linux ioctl #define RNDADDTOENTCNT	_IOW( 'R', 0x01, int )
ioctl_write_ptr!(set_entropy, 'R' as u8, 0x01, u32);

const GET_RANDOM_MAX_OUTPUT: usize = 256;

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

    result
        .join()
        .map_err(|err| format!("Failure in entropy seeding loop. {:?}", err))?
}

fn seed_entropy(entropy_bytes_count: usize, nsm_device: &NSMDevice, random_device: &mut fs::File) -> Result<(), String> {
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
            nsm_io::ErrorCode::Success => {}
            err => return Err(format!("Failed to get random from nsm. {:?}", err)),
        }

        if buf_len == 0 {
            return Err(format!("Nsm returned 0 entropy"));
        }

        // write new entropy seed into /dev/random
        random_device
            .write_all(&mut buf)
            .map_err(|err| format!("Failed to write entropy to /dev/random. {:?}", err))?;

        let entropy_bits = (buf_len * 8) as u32;

        // Now we can increment entropy count of the entropy pool
        // by calling a proper ioctl on /dev/random as described here:
        // https://man7.org/linux/man-pages/man4/random.4.html
        match unsafe { set_entropy(random_device.as_raw_fd(), &entropy_bits) } {
            Ok(result_code) if result_code < 0 => return Err(format!("Ioctl exited with code: {}", result_code)),
            Err(err) => return Err(format!("Ioctl exited with error: {:?}", err)),
            _ => {}
        }
        count += buf_len;
    }

    Ok(())
}

// Wraps NSM descriptor to implement Drop
struct NSMDevice {
    descriptor: i32,
}

impl NSMDevice {
    fn new() -> Result<Self, String> {
        let descriptor = nsm::nsm_lib_init();

        if descriptor < 0 {
            return Err(format!("Failed initializing nsm lib. Returned {}", descriptor));
        }

        Ok(NSMDevice { descriptor })
    }
}

impl Drop for NSMDevice {
    fn drop(&mut self) {
        nsm::nsm_lib_exit(self.descriptor);
    }
}

pub fn write_to_file(path: &Path, data: &str) -> Result<(), String> {
    fs::write(path, data.as_bytes()).map_err(|err| format!("Failed to write data into file {}. {:?}", path.display(), err))
}
