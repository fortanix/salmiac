use async_process::{Command};
use futures::stream::futures_unordered::FuturesUnordered;
use futures::StreamExt;
use ipnetwork::IpNetwork;
use log::{debug, info, warn};
use tokio::task::JoinHandle;
use tokio_vsock::VsockListener as AsyncVsockListener;
use tokio_vsock::VsockStream as AsyncVsockStream;

use crate::network::{
    choose_network_addresses_for_fs_taps, list_network_devices, setup_file_system_tap_devices, setup_network_devices,
    PairedPcapDevice, PairedTapDevice, FS_TAP_MTU,
};
use crate::packet_capture::start_pcap_loops;
use shared::device::{start_tap_loops, ApplicationConfiguration, CCMBackendUrl, GlobalNetworkSettings, SetupMessages};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use shared::{VSOCK_PARENT_CID};
use shared::{extract_enum_value, handle_background_task_exit, UserProgramExitStatus};

use std::env;
use std::fs;
use std::io::Write;
use std::str::FromStr;
use std::net::SocketAddr;

const INSTALLATION_DIR: &str = "/opt/fortanix/enclave-os";

const NBD_CONFIG_FILE: &'static str = "/opt/fortanix/enclave-os/nbd.config";

const NBD_BLOCK_FILE: &'static str = "/opt/fortanix/enclave-os/Blockfile.ext4";

const NBD_PORT: u16 = 7777;

pub async fn run(vsock_port: u32) -> Result<UserProgramExitStatus, String> {
    info!("Awaiting confirmation from enclave.");

    let mut enclave_port = create_vsock_stream(vsock_port).await?;

    info!("Connected to enclave.");

    let setup_result = setup_parent(&mut enclave_port).await?;
    let fs_tap_l3_address = setup_result.file_system_tap.tap_l3_address.ip();

    let use_file_system = extract_enum_value!(enclave_port.read_lv().await?, SetupMessages::UseFileSystem(e) => e)?;
    let mut background_tasks = start_background_tasks(setup_result, use_file_system)?;

    if use_file_system {
        enclave_port.write_lv(&SetupMessages::NBDConfiguration(SocketAddr::new(fs_tap_l3_address, NBD_PORT))).await?;
    }

    let user_program = tokio::spawn(await_user_program_return(enclave_port));

    if !background_tasks.is_empty() {
        tokio::select! {
            result = background_tasks.next() => {
                handle_background_task_exit(result, "pcap loop")
            },
            result = user_program => {
                result.map_err(|err| format!("Join error in user program wait loop. {:?}", err))?
            },
        }
    } else {
        user_program
            .await
            .map_err(|err| format!("Join error in user program wait loop. {:?}", err))?
    }
}

fn write_nbd_config(fs_tap_l3_address: IpNetwork) -> Result<(), String> {
    fs::create_dir_all(INSTALLATION_DIR).map_err(|err| format!("Failed creating {} dir. {:?}", INSTALLATION_DIR, err))?;

    let mut nbd_config_file =
        fs::File::create(NBD_CONFIG_FILE).map_err(|err| format!("Failed creating {} file. {:?}", NBD_CONFIG_FILE, err))?;

    let config = format!(
        "
    [generic]
        includedir = /etc/nbd-server/conf.d
        allowlist = true
        listenaddr = {}
    [enclave-fs]
        authfile =
        exportname = {}",
        fs_tap_l3_address.ip().to_string(),
        NBD_BLOCK_FILE
    );

    nbd_config_file
        .write_all(config.as_bytes())
        .map_err(|err| format!("Failed writing nbd config file. {:?}", err))
}

/// Starts `nbd-server` process and waits until it finishes.
/// `nbd-server` is a background process that runs for the whole duration of the program,
/// which means that this function waits forever in a non-blocking manner and exits only if
/// `nbd-server` finishes with an error.
/// # Returns
/// Exit code, stdout and stderr of `nbd-server` if it finishes.
async fn run_nbd_server(fs_tap_l3_address: IpNetwork, port: u16) -> Result<(), String> {
    write_nbd_config(fs_tap_l3_address)?;

    let mut nbd_command = Command::new("nbd-server");

    let args: [&str; 4] = ["-d", "-C", NBD_CONFIG_FILE, &port.to_string()];
    nbd_command.args(args);

    let nbd_process = nbd_command
        .spawn()
        .map_err(|err| format!("Failed to start NBD server. {:?}", err))?;

    let out = nbd_process
        .output()
        .await
        .map_err(|err| format!("Error while waiting for NBD server to finish: {:?}", err))?;

    let result = format!(
        "NBD server exited with code {}. Stdout: {}. Stderr: {}",
        out.status,
        String::from_utf8(out.stdout.clone()).unwrap_or(format!("Failed decoding stdout to UTF-8, raw output is {:?}", out.stdout)),
        String::from_utf8(out.stderr.clone()).unwrap_or(format!("Failed decoding stderr to UTF-8, raw output is {:?}", out.stderr))
    );

    // NBD server runs forever and can exit only with an error.
    Err(result)
}

fn start_background_tasks(
    parent_setup_result: ParentSetupResult,
    use_file_system: bool
) -> Result<FuturesUnordered<JoinHandle<Result<(), String>>>, String> {
    let result = FuturesUnordered::new();

    for paired_device in parent_setup_result.network_devices {
        let res = start_pcap_loops(paired_device.pcap, paired_device.vsock)?;

        result.push(res.read_handle);
        result.push(res.write_handle);
    }

    let fs_device = parent_setup_result.file_system_tap;
    let fs_tap_loops = start_tap_loops(fs_device.tap, fs_device.vsock, FS_TAP_MTU);

    result.push(fs_tap_loops.read_handle);
    result.push(fs_tap_loops.write_handle);

    if use_file_system {
        let nbd_server = tokio::spawn(run_nbd_server(fs_device.tap_l3_address, NBD_PORT));
        info!("Started nbd server");
        result.push(nbd_server);
    }

    Ok(result)
}

struct ParentSetupResult {
    network_devices: Vec<PairedPcapDevice>,

    file_system_tap: PairedTapDevice,
}

async fn setup_parent(vsock: &mut AsyncVsockStream) -> Result<ParentSetupResult, String> {
    send_application_configuration(vsock).await?;

    let (network_devices, settings_list) = list_network_devices().await?;
    let network_addresses_in_use = settings_list
        .iter()
        .map(|e| match e.self_l3_address {
            IpNetwork::V4(e) => e,
            _ => panic!("Only Ipv4 addresses are supported for network devices!"),
        })
        .collect();

    let paired_network_devices = setup_network_devices(vsock, network_devices, settings_list).await?;

    send_global_network_settings(vsock).await?;

    let file_system_tap = {
        let (parent_address, enclave_address) = choose_network_addresses_for_fs_taps(network_addresses_in_use)?;

        setup_file_system_tap_devices(vsock, parent_address, enclave_address).await?
    };

    communicate_certificates(vsock).await?;

    Ok(ParentSetupResult {
        network_devices: paired_network_devices,
        file_system_tap,
    })
}

async fn send_global_network_settings(enclave_port: &mut AsyncVsockStream) -> Result<(), String> {
    let dns_file = fs::read_to_string("/etc/resolv.conf")
        .map_err(|err| format!("Failed reading parent's /etc/resolv.conf. {:?}", err))?
        .into_bytes();

    let network_settings = GlobalNetworkSettings { dns_file };

    enclave_port
        .write_lv(&SetupMessages::GlobalNetworkSettings(network_settings))
        .await?;

    debug!("Sent global network settings to the enclave.");

    Ok(())
}

async fn await_user_program_return(mut vsock: AsyncVsockStream) -> Result<UserProgramExitStatus, String> {
    extract_enum_value!(vsock.read_lv().await?, SetupMessages::UserProgramExit(status) => status)
}

async fn communicate_certificates(vsock: &mut AsyncVsockStream) -> Result<(), String> {
    // Don't bother looking for a node agent address unless there's at least one certificate configured. This allows us to run
    // with the NODE_AGENT environment variable being unset, if there are no configured certificates.
    let mut node_agent_address: Option<String> = None;

    // Process certificate requests until we get the SetupSuccessful message indicating that the enclave is done with
    // setup. There can be any number of certificate requests, including 0.
    loop {
        let msg: SetupMessages = vsock.read_lv().await?;

        match msg {
            SetupMessages::NoMoreCertificates => return Ok(()),
            SetupMessages::CSR(csr) => {
                let addr = match node_agent_address {
                    Some(ref addr) => addr.clone(),
                    None => {
                        let result = env::var("NODE_AGENT")
                            .map_err(|err| format!("Failed to read NODE_AGENT var. {:?}", err))?;

                        let addr = if !result.starts_with("http://") {
                           "http://".to_string() + &result
                        } else {
                            result
                        };
                        node_agent_address = Some(addr.clone());
                        addr
                    },
                };
                let certificate = em_app::request_issue_certificate(&addr, csr)
                    .map_err(|err| format!("Failed to receive certificate {:?}", err))
                    .and_then(|e| e.certificate.ok_or("No certificate returned".to_string()))?;

                vsock.write_lv(&SetupMessages::Certificate(certificate)).await?;
            },
            other => return Err(format!("While processing certificate requests, expected SetupMessages::CSR(csr) or SetupMessages:SetupSuccessful, but got {:?}",
                                        other)),
        };
    }
}

async fn send_application_configuration(vsock: &mut AsyncVsockStream) -> Result<(), String> {
    let ccm_backend_url = env_var_or_none("CCM_BACKEND").map_or(Ok(CCMBackendUrl::default()), |e| CCMBackendUrl::new(&e))?;

    let id = get_app_config_id();

    let skip_server_verify = env_var_or_none("SKIP_SERVER_VERIFY")
        .map_or(Ok(false), |e| bool::from_str(&e))
        .map_err(|err| format!("Failed converting SKIP_SERVER_VERIFY env var to bool. {:?}", err))?;

    let application_configuration = ApplicationConfiguration {
        id,
        ccm_backend_url,
        skip_server_verify,
    };

    vsock
        .write_lv(&SetupMessages::ApplicationConfig(application_configuration))
        .await
}

async fn create_vsock_stream(port: u32) -> Result<AsyncVsockStream, String> {
    let mut socket = listen_to_parent(port)?;

    accept(&mut socket).await
}

pub(crate) fn listen_to_parent(port: u32) -> Result<AsyncVsockListener, String> {
    AsyncVsockListener::bind(VSOCK_PARENT_CID, port)
        .map_err(|_| format!("Could not bind to cid: {}, port: {}", VSOCK_PARENT_CID, port))
}

pub(crate) async fn accept(listener: &mut AsyncVsockListener) -> Result<AsyncVsockStream, String> {
    listener
        .accept()
        .await
        .map(|r| r.0)
        .map_err(|err| format!("Accept from vsock failed: {:?}", err))
}

fn get_app_config_id() -> Option<String> {
    match env::var("ENCLAVEOS_APPCONFIG_ID").or(env::var("APPCONFIG_ID")) {
        Ok(result) => Some(result),
        Err(err) => {
            warn!(
                "Failed reading env var ENCLAVEOS_APPCONFIG_ID or APPCONFIG_ID, assuming var is not set. {:?}",
                err
            );
            None
        }
    }
}

fn env_var_or_none(var_name: &str) -> Option<String> {
    match env::var(var_name) {
        Ok(result) => Some(result),
        Err(err) => {
            warn!("Failed reading env var {}, assuming var is not set. {:?}", var_name, err);
            None
        }
    }
}
