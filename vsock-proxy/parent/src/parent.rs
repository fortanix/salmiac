/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::{env, fs};

use async_process::Command;
use futures::stream::futures_unordered::FuturesUnordered;
use ipnetwork::IpNetwork;
use log::{debug, error, info, warn};
use parent_lib::{communicate_certificates, setup_file_system, CertificateApi, NBDExportConfig, NBD_EXPORTS};
use shared::models::{ApplicationConfiguration, FileWithPath, GlobalNetworkSettings, SetupMessages, UserProgramExitStatus};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use shared::tap::{start_tap_loops, PRIVATE_TAP_MTU, PRIVATE_TAP_NAME};
use shared::{
    cleanup_tokio_tasks, run_subprocess, run_subprocess_with_output_setup, with_background_tasks, AppLogPortInfo,
    CommandOutputConfig, StreamType, DNS_RESOLV_FILE, HOSTNAME_FILE, HOSTS_FILE, NS_SWITCH_FILE, VSOCK_PARENT_CID,
};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_vsock::{VsockListener as AsyncVsockListener, VsockStream as AsyncVsockStream};

use crate::network::{
    choose_addrs_for_private_taps, list_network_devices, set_up_private_tap_devices, setup_network_devices, PairedPcapDevice,
    PairedTapDevice,
};
use crate::packet_capture::start_pcap_loops;
use crate::ParentConsoleArguments;

const INSTALLATION_DIR: &str = "/opt/fortanix/enclave-os";

const ORIG_ENV_LIST_PATH: &str = "original-parent.env";

const NBD_CONFIG_FILE: &'static str = "/opt/fortanix/enclave-os/nbd.config";

const OVERLAYFS_BLOCKFILE_DIR: &'static str = "/opt/fortanix/enclave-os/overlayfs";

const RW_BLOCK_FILE_OUT: &'static str = "Blockfile-rw.ext4";

// Recommended minimum size is 32Mib because luks2 default header
// size is 16Mib here - https://wiki.archlinux.org/title/dm-crypt/Device_encryption
// Double this value in salmiac to 64 Mib
const MIN_RW_BLOCKFILE_SIZE: usize = 64 * 1024 * 1024;

const VSOCK_PARENT_PORT: u32 = 5006;

const DEFAULT_CPU_COUNT: u8 = 2;

const DEFAULT_MEMORY_SIZE: u64 = 2048;

const NAMESERVER_KEYWORD: &'static str = "nameserver";

const CLIENT_LOG_STREAMS: [StreamType; 2] = [StreamType::Stdout, StreamType::Stderr];

async fn message_handler(enclave: &mut AsyncVsockStream) -> Result<UserProgramExitStatus, String> {
    loop {
        match enclave.read_lv().await? {
            SetupMessages::UserProgramExit(status) => return status,
            SetupMessages::CSR(csr) => match parent_lib::handle_csr_message(enclave, EmAppCertificateApi {}, csr).await {
                Ok(()) => (),
                Err(e) => info!("CSR message handler failed with {e}. Continuing, the enclave will retry later"),
            },
            _r => return Err(format!("Unexpected message while executing user application")),
        }
    }
}

pub(crate) async fn run(args: ParentConsoleArguments) -> Result<UserProgramExitStatus, String> {
    info!("Checking presence of overlayfs parent directory.");
    let overlayfs_parent_dir = Path::new(OVERLAYFS_BLOCKFILE_DIR);
    if !overlayfs_parent_dir.exists() {
        info!("Creating overlayfs directory where the rw encrypted blockfile would be created...");
        fs::create_dir_all(overlayfs_parent_dir).map_err(|e| format!("Unable to create overlayfs parent dir : {:?}", e))?;
    }

    info!("Spawning enclave process.");
    // todo: will be used in https://fortanix.atlassian.net/browse/SALM-300
    let _enclave_process = tokio::spawn(start_nitro_enclave());

    info!("Awaiting confirmation from enclave.");
    let mut enclave_port = create_vsock_stream(VSOCK_PARENT_PORT).await?;

    info!("Connected to enclave.");
    let console_process = tokio::spawn(enables_console_logs());
    // Add enclave processes to a separate list of futures. They will be cleaned up
    // once the parent sends the ExitEnclave message to the enclave port.
    let enclave_tasks = FuturesUnordered::new();
    enclave_tasks.push({
        let _ = enclave_tasks;
        console_process
    });

    send_env_variables(&mut enclave_port).await?;
    send_node_agent_address(&mut enclave_port).await?;
    send_enclave_extra_console_args(&mut enclave_port, args.enclave_extra_args).await?;

    let setup_result = setup_parent(&mut enclave_port, args.rw_block_file_size.to_inner()).await?;
    let tap_l3_address = setup_result.private_tap.tap_l3_address.ip();

    let mut log_listeners = setup_log_listeners(tap_l3_address).await?;
    let mut background_tasks = start_background_tasks(setup_result)?;

    let log_ports = get_log_sock_addrs(&mut log_listeners)?;
    info!("Client log listeners set up.");

    let tcp_log_tasks = run_log_listeners(log_listeners)
        .await
        .map_err(|e| format!("Unable to start app log listeners : {:?}", e))?;

    // Once the client app exits, the sockets between the parent and enclave are closed and these
    // tasks finish. They are not added to background tasks since they finish after client app
    // completes but before enclave exit.
    for log_task in tcp_log_tasks {
        enclave_tasks.push(log_task);
    }

    let (exit_code, mut enclave_port) = with_background_tasks!(background_tasks, {
        setup_file_system(&mut enclave_port, tap_l3_address).await?;

        // Pass the ports which the enclave can connect to for forwarding logs
        enclave_port.write_lv(&SetupMessages::AppLogPort(log_ports)).await?;

        // Start message handler loop, next message can be easily handled in loop
        let exit_code = message_handler(&mut enclave_port).await?;

        Ok((exit_code, enclave_port))
    })?;

    cleanup_tokio_tasks(background_tasks)?;

    send_enclave_exit(&mut enclave_port).await?;

    // Workaround for SALM-298. Kill the nitro-cli console process
    // if it is still waiting for data after enclave exits.
    cleanup_tokio_tasks(enclave_tasks)?;

    Ok(exit_code)
}

// Setup two Tcp servers - one to read stdout and another for stderr of the client program
async fn setup_log_listeners(tap_l3_address: IpAddr) -> Result<Vec<(TcpListener, StreamType)>, String> {
    if env::var("ENCLAVEOS_DEBUG").unwrap_or(" ".to_string()) != "debug" {
        let mut res: Vec<(TcpListener, StreamType)> = Vec::with_capacity(2);
        for stream in CLIENT_LOG_STREAMS {
            let listen = TcpListener::bind(SocketAddr::new(tap_l3_address, 0)).await.map_err(|e| {
                format!(
                    "Unable to setup tcp listener, bind on IP {:?} failed : {:?}",
                    tap_l3_address, e
                )
            })?;
            res.push((listen, stream));
        }
        Ok(res)
    } else {
        Ok(vec![])
    }
}

// Obtain the socket addresses of the tcp listeners which were setup to obtain client
// application logs.
fn get_log_sock_addrs(listeners: &mut Vec<(TcpListener, StreamType)>) -> Result<Vec<AppLogPortInfo>, String> {
    Ok(listeners
        .iter()
        .filter_map(|(tcp_listener, stream_type)| {
            get_tcp_local_addr(tcp_listener).map(|sock_addr| AppLogPortInfo {
                sock_addr,
                stream_type: *stream_type,
            })
        })
        .collect())
}

// Don't fail the app execution if we are not able to forward logs
fn get_tcp_local_addr(tcp_listener: &TcpListener) -> Option<SocketAddr> {
    match tcp_listener.local_addr() {
        Ok(sock_addr) => Some(sock_addr),
        Err(e) => {
            warn!(
                "Unable to obtain log listener {:?} address, failing silently : {:?}",
                tcp_listener, e
            );
            None
        }
    }
}

async fn send_enclave_exit(enclave_port: &mut AsyncVsockStream) -> Result<(), String> {
    let message: Result<SetupMessages, String> = Ok(SetupMessages::ExitEnclave);
    enclave_port.write_lv(&message).await
}

fn filter_env_variables(orig_env_path: PathBuf) -> Result<Vec<(String, String)>, String> {
    let mut runtime_vars: HashMap<String, String> = env::vars().collect();
    info!("Found the following environment variables in parent : {:?}", runtime_vars);

    // "_" is a special var setup by bash that points to the currently executed binary
    // to not leak the binary path into the enclave we remove this var explicitly.
    runtime_vars.remove("_");

    // The ORIG_ENV_LIST_PATH file contains the list of variables which were set in the parent at conversion time.
    let file =
        File::open(orig_env_path.as_path()).map_err(|e| format!("Unable to find parent's original env variables : {}", e))?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let env_line = line.map_err(|e| format!("Unable to read line from file {:?} : {:?}", orig_env_path, e))?;
        // Ill formed env variables will be ignored
        let parent_env_var = env_line.split_once("=").unwrap_or(("", ""));

        filter_parent_env_from_runtime_envs(&mut runtime_vars, parent_env_var);
    }

    Ok(runtime_vars.into_iter().collect())
}

/// Filter the environment variables sent from the parent at runtime.
/// This function modifies a mutable `HashMap` of runtime environment variables by removing a specified key-value pair if certain conditions are met.
/// # Rules for filtering are:
///  - Always pass HOSTNAME
///  - Keep all environment variables which are new (i.e. not present in the parent at conversion
///    time)
///  - Keep environment variables which were present in the parent container but their values
///    have now been updated. The exception to this rule is for the PATH variable.
fn filter_parent_env_from_runtime_envs(runtime_env_vars: &mut HashMap<String, String>, parent_env: (&str, &str)) -> () {
    let (conv_time_env_key, conv_time_env_val) = parent_env;

    if conv_time_env_key != "HOSTNAME" {
        info!("Testing if {:?} does not exist or has been updated.", parent_env);

        match runtime_env_vars.get(conv_time_env_key) {
            Some(value) if value == conv_time_env_val || conv_time_env_key == "PATH" => {
                runtime_env_vars.remove(conv_time_env_key);
            }
            _ => {}
        }
    }
}

async fn send_env_variables(enclave_port: &mut AsyncVsockStream) -> Result<(), String> {
    let filtered_env_vars = filter_env_variables(Path::new(INSTALLATION_DIR).join(ORIG_ENV_LIST_PATH))?;
    info!("Passing these variables to the enclave : {:?}", filtered_env_vars);
    enclave_port.write_lv(&SetupMessages::EnvVariables(filtered_env_vars)).await
}

async fn send_node_agent_address(enclave_port: &mut AsyncVsockStream) -> Result<(), String> {
    let address = parent_lib::node_agent_address();
    info!("Returning node agent: {:?}", address);
    enclave_port.write_lv(&SetupMessages::NodeAgentUrl(address)).await
}

async fn send_enclave_extra_console_args(enclave_port: &mut AsyncVsockStream, arguments: Vec<String>) -> Result<(), String> {
    enclave_port
        .write_lv(&SetupMessages::ExtraUserProgramArguments(arguments))
        .await
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

/// Start the dnsmasq process. dnsmasq is a DNS server/proxy. We configure dnsmasq to listen
/// on the fortanix-tap0 device, so that device must be set up first before we start dnsmasq.
/// dnsmasq will refuse to run if the configured interface is not present when it starts.
///
/// TODO: We should monitor the child process and restart it if crashes or exits.
async fn run_dnsmasq() -> Result<(), String> {
    run_subprocess("/usr/sbin/dnsmasq", &["--keep-in-foreground"]).await
}

async fn start_accepting_connections(listen: TcpListener, stream_type: StreamType) -> Result<(), String> {
    // We need to accept one connection which is expected from the enclave side
    info!(
        "Waiting for connections on {:?}",
        listen
            .local_addr()
            .map_err(|e| format!("unable to get local addr for listener {:?}", e))?
    );
    let (mut stream, _socket) = listen
        .accept()
        .await
        .map_err(|e| format!("Unable to accept a new connection on the log listener : {:?}", e))?;

    // Copy data from the tcp streams to the respective stdout/stderr of the parent console
    // tokio::io::copy continues to run until the stream returns an EOF, at which point it returns Ok(0)
    match stream_type {
        StreamType::Stdout => {
            let _copy_size = tokio::io::copy(&mut stream, &mut tokio::io::stdout())
                .await
                .map_err(|e| format!("Unable to copy data from socket {:?} to stdout of parent : {:?}", stream, e))?;
        }
        StreamType::Stderr => {
            let _copy_size = tokio::io::copy(&mut stream, &mut tokio::io::stderr())
                .await
                .map_err(|e| format!("Unable to copy data from socket {:?} to stderr of parent : {:?}", stream, e))?;
        }
    }
    Ok(())
}
async fn run_log_listeners(listeners_info: Vec<(TcpListener, StreamType)>) -> Result<Vec<JoinHandle<Result<(), String>>>, ()> {
    let mut tasks = vec![];
    for (tcp_listener, stream_type) in listeners_info {
        tasks.push(tokio::spawn(start_accepting_connections(tcp_listener, stream_type)));
    }
    Ok(tasks)
}

async fn enables_console_logs() -> Result<(), String> {
    if env::var("ENCLAVEOS_DEBUG").unwrap_or(" ".to_string()) == "debug" {
        info!("ENCLAVEOS_DEBUG set, fetching enclave console logs.");
        run_subprocess(
            "nitro-cli",
            &["console", "--enclave-name", "enclave", "--disconnect-timeout", "30"],
        )
        .await?;
    }
    Ok(())
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

fn start_background_tasks(
    parent_setup_result: ParentSetupResult,
) -> Result<FuturesUnordered<JoinHandle<Result<(), String>>>, String> {
    let result = FuturesUnordered::new();

    for paired_device in parent_setup_result.network_devices {
        let res = start_pcap_loops(paired_device.pcap, paired_device.vsock)?;

        result.push(res.pcap_to_vsock);
        result.push(res.vsock_to_pcap);
    }

    let private_device = parent_setup_result.private_tap;
    let private_tap_loops = start_tap_loops(private_device.tap, private_device.vsock, PRIVATE_TAP_MTU);

    result.push(private_tap_loops.tap_to_vsock);
    result.push(private_tap_loops.vsock_to_tap);

    write_nbd_config(private_device.tap_l3_address.ip(), NBD_EXPORTS)?;

    for export_config in NBD_EXPORTS {
        let nbd_process = tokio::spawn(run_nbd_server(export_config.port));
        info!(
            "Started nbd server on port {} serving block file {}",
            export_config.port, export_config.block_file_path
        );

        result.push(nbd_process);
    }

    if parent_setup_result.start_dnsmasq {
        let dnsmasq_process = tokio::spawn(run_dnsmasq());
        info!("Started dnsmasq to service enclave DNS queries.");
        result.push(dnsmasq_process);
    } else {
        info!("Dnsmasq service not required.");
    }

    // Running tcpdump somehow solves the network hang when workflow is being requested by the enclave.
    // The cause of that is currently unknown and will be investigated in: https://fortanix.atlassian.net/browse/SALM-477
    // After investigation finishes this quick fix will be removed.
    if env::var("IS_EKS").unwrap_or("".to_string()) == "true" {
        info!("Started tcpdump to make work flow retrieval work on EKS.");
        let tcpdump = tokio::spawn(async {
            // We set stdin/out to null for subprocess to not pollute the console with tcpdump logs
            // and to prevent anyone from sniffing it's output
            run_subprocess_with_output_setup("tcpdump", &[], CommandOutputConfig::all_null())
                .await
                .map(|_| ())
        });
        result.push(tcpdump);
    }

    Ok(result)
}

struct ParentSetupResult {
    network_devices: Vec<PairedPcapDevice>,

    private_tap: PairedTapDevice,

    start_dnsmasq: bool,
}

struct ResolvConfResult {
    resolv_conf_file: FileWithPath,

    start_dnsmasq: bool,
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

    let (parent_address, enclave_address) = choose_addrs_for_private_taps(network_addresses_in_use)?;

    let start_dnsmasq = send_global_network_settings(parent_address, vsock).await?;

    let private_tap = {
        create_rw_block_file(rw_block_file_size, Path::new(OVERLAYFS_BLOCKFILE_DIR).join(RW_BLOCK_FILE_OUT))?;
        set_up_private_tap_devices(vsock, parent_address, PRIVATE_TAP_NAME, enclave_address, PRIVATE_TAP_NAME).await?
    };

    communicate_certificates(vsock, EmAppCertificateApi {}).await?;

    Ok(ParentSetupResult {
        network_devices: paired_network_devices,
        private_tap,
        start_dnsmasq,
    })
}

/// Customize the resolv.conf before we send it to the enclave. In certain Docker network configurations,
/// such as Docker custom networks, the parent will be configured with a DNS server listening on the
/// localhost network at 127.0.0.11 (not a typo). The enclave cannot directly access the parent's loopback
/// network, as it will be handled by the enclave's own loopback network. So instead of telling the enclave
/// to use the parent's configured upstream DNS server, we run a DNS server in the parent, and tell the
/// enclave to use that DNS server to resolve its own requests.
///
/// We remove any nameserver configurations from the parent's resolv.conf and add a single nameserver
/// parameter with the parent's address on the network shared between the parent and the enclave. We leave
/// the rest of the resolv.conf alone, so the enclave will get any other configuration specified, such as
/// domain search paths or other DNS options.
///
/// Note that this function does NOT modify the parent's resolv.conf. It just returns the modified version
/// that should be used by the enclave.
fn customize_resolv_conf(nameserver_address: IpNetwork) -> Result<ResolvConfResult, String> {
    let parent_resolv = File::open(DNS_RESOLV_FILE).map_err(|err| format!("Could not open {}. {:?}", DNS_RESOLV_FILE, err))?;

    let mut enclave_resolv: Vec<u8> = vec![];
    let mut start_dnsmasq: bool = false;
    let lines = BufReader::new(parent_resolv).lines();

    for line in lines {
        let line = line.map_err(|err| format!("unable to read file {}. {:?}", DNS_RESOLV_FILE, err))?;
        // According to the man page for resolv.conf, the keyword (like nameserver) must start the line, so we don't
        // have to trim before looking for the "nameserver" keyword. We do need to look for at least one whitespace
        // character, since the keyword must be followed by whitespace. There don't currently appear to be any
        // config keywords that begin with "nameserver" that aren't "nameserver", but possibly new keywords could
        // be added in the future.
        if !(line.starts_with(NAMESERVER_KEYWORD)
            && line
                .chars()
                .nth(NAMESERVER_KEYWORD.len())
                .map(|e| e.is_whitespace())
                .unwrap_or_default())
        {
            enclave_resolv.extend_from_slice(line.as_bytes());
        } else {
            let dns_resolver_addr = line.split_at(NAMESERVER_KEYWORD.len()).1.trim();
            if dns_resolver_addr.starts_with("127.0.0.") {
                info!(
                    "Updating resolv.conf data sent to enclave with parent's tap device address {:?}",
                    nameserver_address.ip()
                );
                enclave_resolv.extend_from_slice(format!("nameserver {:?}\n", nameserver_address.ip()).as_bytes());
                start_dnsmasq = true;
            } else {
                enclave_resolv.extend_from_slice(line.as_bytes());
            }
        }
        // We have to manually insert a newline after each line, because lines() consumes the newlines.
        enclave_resolv.extend_from_slice("\n".as_bytes());
    }

    let result = ResolvConfResult {
        resolv_conf_file: FileWithPath {
            path: DNS_RESOLV_FILE.to_string(),
            data: enclave_resolv,
        },
        start_dnsmasq,
    };

    Ok(result)
}

async fn send_global_network_settings(
    nameserver_address: IpNetwork,
    enclave_port: &mut AsyncVsockStream,
) -> Result<bool, String> {
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

    let dns_file = customize_resolv_conf(nameserver_address)?;
    let hosts_file = read_file(HOSTS_FILE)?;
    let host_name_file = read_file(HOSTNAME_FILE)?;
    let ns_switch_file = read_file(NS_SWITCH_FILE)?;

    let network_settings = GlobalNetworkSettings {
        hostname,
        global_settings_list: vec![dns_file.resolv_conf_file, hosts_file, host_name_file, ns_switch_file],
    };

    enclave_port
        .write_lv(&SetupMessages::GlobalNetworkSettings(network_settings))
        .await?;

    debug!("Sent global network settings to the enclave.");

    Ok(dns_file.start_dnsmasq)
}

#[derive(Clone)]
struct EmAppCertificateApi {}
impl CertificateApi for EmAppCertificateApi {
    fn request_issue_certificate(&self, url: &str, csr_pem: String) -> Result<String, String> {
        em_app::request_issue_certificate(url, csr_pem)
            .map_err(|err| format!("Failed to receive certificate {:?}", err))
            .and_then(|e| e.certificate.ok_or("No certificate returned".to_string()))
    }
}

async fn send_application_configuration(vsock: &mut AsyncVsockStream) -> Result<(), String> {
    let id = get_app_config_id();

    let skip_server_verify = env_var_or_none("SKIP_SERVER_VERIFY")
        .map_or(Ok(false), |e| bool::from_str(&e))
        .map_err(|err| format!("Failed converting SKIP_SERVER_VERIFY env var to bool. {:?}", err))?;

    let application_configuration = ApplicationConfiguration { id, skip_server_verify };

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

fn check_rw_min_size_requirement(size: usize) -> Result<(), String> {
    if size < MIN_RW_BLOCKFILE_SIZE {
        return Err(format!(
            "Existing file size {} doesn't reach minimum RW block file size requirements of {}",
            size, MIN_RW_BLOCKFILE_SIZE
        ));
    }
    Ok(())
}

fn create_rw_block_file(size: u64, path: PathBuf) -> Result<(), String> {
    match fs::metadata(path.clone()) {
        Ok(md) => {
            let real_size = md.len();
            check_rw_min_size_requirement(real_size as usize)?;
            info!(
                "{:?} of size {:?} already exists, skipping creating a new blockfile",
                path.as_path(),
                real_size
            );
            return Ok(());
        }
        Err(_) => {
            check_rw_min_size_requirement(size as usize)?;
            // Create a new file only if it does not exist, otherwise open an existing file
            // and return the file pointer. We need this to ensure that when a docker container
            // restarts, it reuses the existing blockfile which contains state from the previous
            // run rather than create a new blockfile which overwrites the previous rw layer.
            let block_file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(path.as_path())
                .map_err(|err| format!("Failed creating RW block file {:?}. {:?}", path.as_path(), err))?;

            info!("Setting RW blockfile size to {:?}", size);
            block_file.set_len(size).map_err(|err| {
                format!(
                    "Failed truncating RW block file {:?} to size {}. {:?}",
                    path.as_path(),
                    size,
                    err
                )
            })?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::File;
    use std::path::PathBuf;

    use tempdir::TempDir;

    use crate::parent::{create_rw_block_file, filter_parent_env_from_runtime_envs, MIN_RW_BLOCKFILE_SIZE};

    // Create a temporary directory. Create a file of specified size in the directory.
    // If size is set to 0, skip creation of file.
    fn setup_rw_blockfile(testname: &str, size: usize) {
        let dir = TempDir::new(testname.as_ref()).expect("Can't create temp dir");

        if size > 0 {
            let file_path = dir.path().join(testname);
            let file = File::create(file_path).expect("Can't create test file path");
            file.set_len(size as u64).expect("Unable to set size of test file");
        }
    }

    // Given the input params to create_rw_block_file, check if the result of the
    // function matches the status
    fn check_create_rw_block_file_res(path: &str, size: usize, success: bool) {
        if success {
            create_rw_block_file(size as u64, PathBuf::from(path)).expect("Unexpected failure");
        } else {
            create_rw_block_file(size as u64, PathBuf::from(path)).expect_err("Unexpected success");
        }
    }

    #[test]
    fn test_create_rw_block_file() {
        // List of test cases - each element in the vector consists of 4 values:
        // (testname, actual block file size, expected block file size, test status)
        // actual block file size - used by the setup function to create a file
        // of the specified size
        // expected block file size - input to the create_rw_block_file function which is being
        // tested here
        // test status - expected test result - whether it is expected to succeed or fail
        let testcases: Vec<(&str, usize, usize, bool)> = vec![
            ("existing_min_size_file", MIN_RW_BLOCKFILE_SIZE, MIN_RW_BLOCKFILE_SIZE, true),
            ("existing_less_than_min_size_file", 10 * 1024 * 1024, 10 * 1024 * 1024, false),
            ("nonexistent_file", 0, 70 * 1024 * 1024, true),
            ("nonexistent_size_check", 0, 10, false),
        ];

        for testcase in testcases {
            setup_rw_blockfile(testcase.0, testcase.1);
            check_create_rw_block_file_res(testcase.0, testcase.2, testcase.3);
        }
    }

    #[test]
    fn test_runtime_hostname_is_not_removed() {
        let mut runtime_env_vars = HashMap::new();
        runtime_env_vars.insert("HOSTNAME".to_string(), "my-new-host".to_string());

        filter_parent_env_from_runtime_envs(&mut runtime_env_vars, ("HOSTNAME", "my-old-host"));

        // Ensure the entry remains unchanged
        assert_eq!(runtime_env_vars.get("HOSTNAME"), Some(&"my-new-host".to_string()));
    }

    #[test]
    fn test_runtime_path_key_is_removed() {
        let mut runtime_env_vars = HashMap::new();
        runtime_env_vars.insert("PATH".to_string(), "old_value".to_string());

        filter_parent_env_from_runtime_envs(&mut runtime_env_vars, ("PATH", "new_value"));

        // Ensure the key was removed
        assert!(runtime_env_vars.get("PATH").is_none());
    }

    #[test]
    fn test_runtime_key_not_removed_when_values_dont_match() {
        let mut runtime_env_vars = HashMap::new();
        runtime_env_vars.insert("MY_VAR".to_string(), "new_value".to_string());

        filter_parent_env_from_runtime_envs(&mut runtime_env_vars, ("MY_VAR", "old_value"));

        // Ensure the key was not removed
        assert_eq!(runtime_env_vars.get("MY_VAR"), Some(&"new_value".to_string()));
    }

    #[test]
    fn test_runtime_key_not_removed_when_not_present() {
        let mut runtime_env_vars = HashMap::new();
        runtime_env_vars.insert("RUNTIME_VAR".to_string(), "runtime_value".to_string());

        filter_parent_env_from_runtime_envs(&mut runtime_env_vars, ("MY_VAR", "value"));

        // Ensure the key was not removed
        assert!(runtime_env_vars.get("RUNTIME_VAR").is_some());
    }

    #[test]
    fn test_runtime_key_removed_when_values_are_the_same() {
        let mut runtime_env_vars = HashMap::new();
        runtime_env_vars.insert("MY_VAR".to_string(), "value".to_string());

        filter_parent_env_from_runtime_envs(&mut runtime_env_vars, ("MY_VAR", "value"));

        // Ensure the key was removed
        assert!(runtime_env_vars.get("MY_VAR").is_none());
    }
}
