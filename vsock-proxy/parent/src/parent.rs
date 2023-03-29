use async_process::Command;
use futures::stream::futures_unordered::FuturesUnordered;
use ipnetwork::IpNetwork;
use log::{debug, info, warn};
use shared::run_subprocess;
use tokio::task::JoinHandle;
use tokio_vsock::VsockListener as AsyncVsockListener;
use tokio_vsock::VsockStream as AsyncVsockStream;

use crate::network::{
    choose_network_addresses_for_fs_taps, list_network_devices, setup_file_system_tap_devices, setup_network_devices,
    PairedPcapDevice, PairedTapDevice, FS_TAP_MTU,
};
use crate::packet_capture::start_pcap_loops;
use crate::ParentConsoleArguments;
use shared::models::{
    ApplicationConfiguration, CCMBackendUrl, FileWithPath, GlobalNetworkSettings, NBDConfiguration, NBDExport, SetupMessages,
    UserProgramExitStatus,
};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use shared::tap::start_tap_loops;
use shared::{extract_enum_value, with_background_tasks};
use shared::{VSOCK_PARENT_CID, VSOCK_PARENT_PORT};

use std::env;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::str::FromStr;

const INSTALLATION_DIR: &str = "/opt/fortanix/enclave-os";

const NBD_CONFIG_FILE: &'static str = "/opt/fortanix/enclave-os/nbd.config";

const RW_BLOCK_FILE_OUT: &'static str = "/opt/fortanix/enclave-os/Blockfile-rw.ext4";

const NBD_EXPORTS: &'static [NBDExportConfig] = &[
    NBDExportConfig {
        name: "enclave-fs",
        block_file_path: "/opt/fortanix/enclave-os/Blockfile.ext4",
        port: 7777,
        is_read_only: true,
    },
    NBDExportConfig {
        name: "enclave-rw-fs",
        block_file_path: "/opt/fortanix/enclave-os/Blockfile-rw.ext4",
        port: 7778,
        is_read_only: false,
    },
];

const DEFAULT_CPU_COUNT: u8 = 2;

const DEFAULT_MEMORY_SIZE: u64 = 2048;

pub(crate) async fn run(args: ParentConsoleArguments) -> Result<UserProgramExitStatus, String> {
    info!("Spawning enclave process.");
    // todo: will be used in https://fortanix.atlassian.net/browse/SALM-300
    let _enclave_process = tokio::spawn(start_nitro_enclave());

    info!("Awaiting confirmation from enclave.");
    let mut enclave_port = create_vsock_stream(VSOCK_PARENT_PORT).await?;

    info!("Connected to enclave. Fetching console logs.");
    let console_process = tokio::spawn(enables_console_logs());

    // Add enclave processes to a separate list of futures. They will be cleaned up
    // once the parent sends the ExitEnclave message to the enclave port.
    let enclave_tasks = FuturesUnordered::new();
    enclave_tasks.push({
        let _ = enclave_tasks;
        console_process
    });

    send_env_variables(&mut enclave_port).await?;
    send_enclave_extra_console_args(&mut enclave_port, args.enclave_extra_args).await?;

    let setup_result = setup_parent(&mut enclave_port, args.rw_block_file_size.to_inner()).await?;
    let fs_tap_l3_address = setup_result.file_system_tap.tap_l3_address.ip();

    let mut background_tasks = start_background_tasks(setup_result)?;

    let (exit_code, mut enclave_port) = with_background_tasks!(background_tasks, {

        send_nbd_configuration(&mut enclave_port, fs_tap_l3_address).await?;

        let user_program = tokio::spawn(await_user_program_return(enclave_port));

        user_program
            .await
            .map_err(|err| format!("Join error in user program wait loop. {:?}", err))?
    })?;

    cleanup(background_tasks)?;

    send_enclave_exit(&mut enclave_port).await?;

    // Workaround for SALM-298. Kill the nitro-cli console process
    // if it is still waiting for data after enclave exits.
    cleanup(enclave_tasks)?;

    Ok(exit_code)
}

fn cleanup(background_tasks: FuturesUnordered<JoinHandle<Result<(), String>>>) -> Result<(), String> {
    for background_task in &background_tasks {
        while !background_task.is_finished() {
            background_task.abort();
        }
    }

    info!("All background tasks have exited successfully.");
    Ok(())
}

async fn send_enclave_exit(enclave_port: &mut AsyncVsockStream) -> Result<(), String> {
    enclave_port.write_lv(&SetupMessages::ExitEnclave).await
}

async fn send_env_variables(enclave_port: &mut AsyncVsockStream) -> Result<(), String> {
    let runtime_vars: Vec<(String, String)> = env::vars().collect();
    enclave_port.write_lv(&SetupMessages::EnvVariables(runtime_vars)).await
}

async fn send_enclave_extra_console_args(enclave_port: &mut AsyncVsockStream, arguments: Vec<String>) -> Result<(), String> {
    enclave_port
        .write_lv(&SetupMessages::ExtraUserProgramArguments(arguments))
        .await
}

async fn send_nbd_configuration(enclave_port: &mut AsyncVsockStream, fs_tap_l3_address: IpAddr) -> Result<(), String> {
    let exports = NBD_EXPORTS
        .iter()
        .map(|e| NBDExport {
            name: e.name.to_string(),
            port: e.port,
        })
        .collect();

    let configuration = NBDConfiguration {
        address: fs_tap_l3_address,
        exports,
    };

    enclave_port.write_lv(&SetupMessages::NBDConfiguration(configuration)).await
}

struct NBDExportConfig {
    pub name: &'static str,

    pub block_file_path: &'static str,

    pub port: u16,

    pub is_read_only: bool,
}

fn write_nbd_config(l3_address: IpAddr, exports: &[NBDExportConfig]) -> Result<(), String> {
    fs::create_dir_all(INSTALLATION_DIR).map_err(|err| format!("Failed creating {} dir. {:?}", INSTALLATION_DIR, err))?;

    let mut nbd_config_file =
        fs::File::create(NBD_CONFIG_FILE).map_err(|err| format!("Failed creating {} file. {:?}", NBD_CONFIG_FILE, err))?;

    let mut config = format!(
        "
        [generic]
            includedir = /etc/nbd-server/conf.d
            allowlist = true
            listenaddr = {}
    ",
        l3_address.to_string()
    );

    for export in exports {
        let export_configuration = format!(
            "
            [{}]
                authfile =
                exportname = {}
                readonly = {}
                port = {}",
            export.name, export.block_file_path, export.is_read_only, export.port
        );
        config.push_str(&export_configuration);
    }

    debug!("NBD config is {}", config);

    nbd_config_file
        .write_all(config.as_bytes())
        .map_err(|err| format!("Failed writing nbd config file. {:?}", err))
}

/// Starts `nbd-server` process and waits until it finishes.
/// `nbd-server` is a background process that runs for the whole duration of the
/// program, which means that this function waits forever in a non-blocking
/// manner and exits only if `nbd-server` finishes with an error.
/// # Returns
/// Exit code, stdout and stderr of `nbd-server` if it finishes.
async fn run_nbd_server(port: u16) -> Result<(), String> {
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

    if out.status.success() {
        Ok(())
    } else {
        let result = format!(
            "NBD server exited with code {}. Stdout: {}. Stderr: {}",
            out.status,
            String::from_utf8(out.stdout.clone())
                .unwrap_or(format!("Failed decoding stdout to UTF-8, raw output is {:?}", out.stdout)),
            String::from_utf8(out.stderr.clone())
                .unwrap_or(format!("Failed decoding stderr to UTF-8, raw output is {:?}", out.stderr))
        );

        Err(result)
    }
}
async fn enables_console_logs() -> Result<(), String> {
    run_subprocess(
        "nitro-cli",
        &["console", "--enclave-name", "enclave", "--disconnect-timeout", "30"],
    )
    .await
}

async fn start_nitro_enclave() -> Result<(), String> {
    let cpu_count = env::var("CPU_COUNT").unwrap_or(DEFAULT_CPU_COUNT.to_string());
    let memsize = env::var("MEM_SIZE").unwrap_or(DEFAULT_MEMORY_SIZE.to_string());

    let command = "nitro-cli";
    let mut args = vec![
        "run-enclave",
        "--eif-path",
        "/opt/fortanix/enclave-os/enclave.eif",
        "--cpu-count",
        &cpu_count,
        "--memory",
        &memsize,
    ];
    if env::var("ENCLAVEOS_DEBUG").unwrap_or(" ".to_string()) == "debug" {
        args.push("--debug-mode");
    }

    run_subprocess(command, &args).await
}

fn start_background_tasks(parent_setup_result: ParentSetupResult) -> Result<FuturesUnordered<JoinHandle<Result<(), String>>>, String> {
    let result = FuturesUnordered::new();

    for paired_device in parent_setup_result.network_devices {
        let res = start_pcap_loops(paired_device.pcap, paired_device.vsock)?;

        result.push(res.pcap_to_vsock);
        result.push(res.vsock_to_pcap);
    }

    let fs_device = parent_setup_result.file_system_tap;
    let fs_tap_loops = start_tap_loops(fs_device.tap, fs_device.vsock, FS_TAP_MTU);

    result.push(fs_tap_loops.tap_to_vsock);
    result.push(fs_tap_loops.vsock_to_tap);

    write_nbd_config(fs_device.tap_l3_address.ip(), NBD_EXPORTS)?;

    for export_config in NBD_EXPORTS {
        let nbd_process = tokio::spawn(run_nbd_server(export_config.port));
        info!("Started nbd server serving block file {}", export_config.block_file_path);

        result.push(nbd_process);
    }

    Ok(result)
}

struct ParentSetupResult {
    network_devices: Vec<PairedPcapDevice>,

    file_system_tap: PairedTapDevice,
}

async fn setup_parent(vsock: &mut AsyncVsockStream, rw_block_file_size: u64) -> Result<ParentSetupResult, String> {
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

        create_rw_block_file(rw_block_file_size)?;
        info!("RW Block file of size {} bytes has been created.", rw_block_file_size);

        setup_file_system_tap_devices(vsock, parent_address, enclave_address).await?
    };

    communicate_certificates(vsock).await?;

    Ok(ParentSetupResult {
        network_devices: paired_network_devices,
        file_system_tap,
    })
}

async fn send_global_network_settings(enclave_port: &mut AsyncVsockStream) -> Result<(), String> {
    const DNS_RESOLV_FILE: &'static str = "/etc/resolv.conf";
    const HOSTS_FILE: &'static str = "/etc/hosts";
    const HOSTNAME_FILE: &'static str = "/etc/hostname";

    fn read_file(path: &str) -> Result<FileWithPath, String> {
        fs::read_to_string(path)
            .map(|e| FileWithPath {
                path: path.to_string(),
                data: e.into_bytes(),
            })
            .map_err(|err| format!("Failed reading parent's {} file. {:?}", path, err))
    }

    let raw_hostname = nix::unistd::gethostname().map_err(|err| format!("Failed reading host name. {:?}", err))?;

    let hostname = raw_hostname
        .into_string()
        .map_err(|err| format!("Failed converting host name to string. {:?}", err))?;

    let dns_file = read_file(DNS_RESOLV_FILE)?;
    let hosts_file = read_file(HOSTS_FILE)?;
    let host_name_file = read_file(HOSTNAME_FILE)?;

    let network_settings = GlobalNetworkSettings {
        hostname,
        global_settings_list: vec![dns_file, hosts_file, host_name_file],
    };

    enclave_port
        .write_lv(&SetupMessages::GlobalNetworkSettings(network_settings))
        .await?;

    debug!("Sent global network settings to the enclave.");

    Ok(())
}

async fn await_user_program_return(mut vsock: AsyncVsockStream) -> Result<(UserProgramExitStatus, AsyncVsockStream), String> {
    let result = extract_enum_value!(vsock.read_lv().await?, SetupMessages::UserProgramExit(status) => status)?;

    Ok((result, vsock))
}

async fn communicate_certificates(vsock: &mut AsyncVsockStream) -> Result<(), String> {
    // Don't bother looking for a node agent address unless there's at least one
    // certificate configured. This allows us to run with the NODE_AGENT
    // environment variable being unset, if there are no configured certificates.
    let mut node_agent_address: Option<String> = None;

    // Process certificate requests until we get the SetupSuccessful message
    // indicating that the enclave is done with setup. There can be any number
    // of certificate requests, including 0.
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
            warn!("Env var ENCLAVEOS_APPCONFIG_ID or APPCONFIG_ID is not set. {:?}", err);
            None
        }
    }
}

fn env_var_or_none(var_name: &str) -> Option<String> {
    match env::var(var_name) {
        Ok(result) => Some(result),
        Err(err) => {
            warn!("Env var {} is not set. {:?}", var_name, err);
            None
        }
    }
}

fn create_rw_block_file(size: u64) -> Result<(), String> {
    let block_file = fs::File::create(RW_BLOCK_FILE_OUT)
        .map_err(|err| format!("Failed creating RW block file {}. {:?}", RW_BLOCK_FILE_OUT, err))?;

    block_file.set_len(size).map_err(|err| {
        format!(
            "Failed truncating RW block file {} to size {}. {:?}",
            RW_BLOCK_FILE_OUT, size, err
        )
    })?;

    Ok(())
}
