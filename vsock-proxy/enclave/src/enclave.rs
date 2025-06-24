/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use chrono::Utc;
use std::convert::{From, TryFrom};
use std::fs;
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::string::ToString;
use api_model::converter::CertificateConfig;
use api_model::enclave::{CcmBackendUrl, EnclaveManifest};
use async_process::{Child, Command};
use async_trait::async_trait;
use em_client::Sha256Hash;
use futures::io::{BufReader, Lines};
use futures::stream::FuturesUnordered;
use futures::{AsyncBufReadExt, StreamExt};
use log::{debug, error, info, warn};
use nix::net::if_::if_nametoindex;
use shared::models::{
    ApplicationConfiguration, NBDConfiguration, NetworkDeviceSettings, PrivateNetworkDeviceSettings, SetupMessages,
    UserProgramExitStatus,
};
use shared::netlink::arp::NetlinkARP;
use shared::netlink::route::NetlinkRoute;
use shared::netlink::{Netlink, NetlinkCommon};
use shared::socket::{AsyncVsockStream as ParentStream, AsyncReadLvStream, AsyncWriteLvStream};
use shared::tap::{create_async_tap_device, start_tap_loops, tap_device_config};
use shared::{
    cleanup_tokio_tasks, extract_enum_value, with_background_tasks, AppLogPortInfo, StreamType, HOSTNAME_FILE, HOSTS_FILE,
    NS_SWITCH_FILE, VSOCK_PARENT_CID,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{MutexGuard, Notify};
use tokio::task::JoinHandle;
use tokio::time::{self as tokio_time, Duration};
use tokio_vsock::VsockStream as AsyncVsockStream;
use tun::{AsyncDevice, Device};

use crate::app_configuration::{setup_application_configuration, EmAppApplicationConfiguration, EmAppCredentials};
use crate::certificate::{self, CertificatePaths, create_signer_key, default_certificate, request_certificate, write_certificate, CSRApi, CertificateResult, CertificateWithPath, EmAppCSRApi, DEFAULT_CERT_DIR, DEFAULT_CERT_RSA_KEY_SIZE};
use crate::dsm_key_config::ClientConnectionInfo;
use crate::file_system::{
    close_dm_crypt_device, close_dm_verity_volume, copy_dns_file_to_mount, copy_startup_binary_to_mount,
    create_fortanix_directories, create_overlay_dirs, fetch_fs_mount_options, get_available_encrypted_space,
    mount_file_system_nodes, mount_overlay_fs, mount_read_only_file_system, mount_read_write_file_system, run_nbd_client,
    setup_dm_verity, unmount_file_system_nodes, unmount_overlay_fs, DMVerityConfig, FileSystemNode, ENCLAVE_FS_OVERLAY_ROOT,
};

const STARTUP_BINARY: &str = "/enclave-startup";

const DEBUG_SHELL_ENV_VAR: &str = "ENCLAVEOS_DEBUG_SHELL";

const FILE_SYSTEM_NODES: &'static [FileSystemNode] = &[
    FileSystemNode::Proc,
    FileSystemNode::TreeNode("/sys"),
    FileSystemNode::TreeNode("/dev"),
    FileSystemNode::TreeNode("/tmp"),
    FileSystemNode::File(HOSTNAME_FILE),
    FileSystemNode::File(HOSTS_FILE),
    FileSystemNode::File(NS_SWITCH_FILE),
];

/// The time duration before expiry a cert renewal is attempted
const CERT_RENEWAL_BEFORE_EXPIRY: Duration = Duration::from_secs(5 * 60 * 60 * 24 /* 5 days */);

/// The interval between certs are checked for renewal
const CERT_RENEWAL_INTERVAL_RELEASE: Duration = Duration::from_secs(1 * 60 * 60 /* 1 hour */);
const CERT_RENEWAL_INTERVAL_DEBUG: Duration = Duration::from_secs(20 /* 20 sec */);

fn default_cert_dir() -> PathBuf {
    PathBuf::from(ENCLAVE_FS_OVERLAY_ROOT)
        .join(DEFAULT_CERT_DIR.strip_prefix("/").unwrap_or_default())
}

async fn auto_cert_renewal(parent: &mut MutexGuard<'_, AsyncVsockStream>, app_config_id: &Option<String>, cert_config: &CertificateConfig) -> Result<bool, String> {
    let cert_path = cert_config.certificate_path(Path::new(ENCLAVE_FS_OVERLAY_ROOT));
    let cert = fs::read_to_string(&cert_path).map_err(|e| e.to_string())?;
    let expiry_date = certificate::get_certificate_expiry(&cert)?
        .and_utc();
    if expiry_date < Utc::now() + CERT_RENEWAL_BEFORE_EXPIRY {
        let mut cert = setup_enclave_certification(
            parent.deref_mut(),
            &EmAppCSRApi{},
            app_config_id,
            &cert_config,
            Path::new(ENCLAVE_FS_OVERLAY_ROOT)).await?;

        write_certificate(&mut cert, Some(default_cert_dir()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn auto_cert_renewals(parent: ParentStream, environment_setup_completed: Arc<Notify>, app_config_id: &Option<String>, mut cert_settings: Vec<CertificateConfig>, is_debug: bool, skip_def_cert_req: bool) -> Result<(), String> {
    environment_setup_completed.notified().await;

    loop {
        let mut parent_guard = parent.lock().await;

        info!("Checking if certificates need to be renewed.");

        if !skip_def_cert_req && cert_settings.is_empty() {
            cert_settings.push(default_certificate());
        }

        // Zero or more certificate requests.
        for cert_config in &cert_settings {
            let cert_path = cert_config.certificate_path(Path::new(ENCLAVE_FS_OVERLAY_ROOT));
            match auto_cert_renewal(&mut parent_guard, app_config_id, &cert_config).await {
                Ok(true) => info!("Certificate at {} renewed", cert_path.display()),
                Ok(false) => info!("Certificate at {} is still valid for longer than {} hours", cert_path.display(), CERT_RENEWAL_BEFORE_EXPIRY.as_secs() / 60 / 60),
                Err(e) => error!("Error encountered considering {} cert for renewal (error: {}), continuing", cert_path.display(), e),
            }
        }

        drop(parent_guard);

        let sleep_duration = if is_debug {
            CERT_RENEWAL_INTERVAL_DEBUG
        } else {
            CERT_RENEWAL_INTERVAL_RELEASE
        };
        info!("End certificate renewal cycle, sleeping for {} seconds", sleep_duration.as_secs());

        tokio_time::sleep(sleep_duration).await;
    }
}

pub(crate) async fn run(vsock_port: u32, settings_path: &Path) -> Result<UserProgramExitStatus, String> {
    let mut parent_port = connect_to_parent_async(vsock_port).await?;

    let (setup_result, networking_setup_result) = startup(&mut parent_port, settings_path).await?;

    let hostname = networking_setup_result.hostname.clone();
    // Background tasks are futures that run for the whole duration of the enclave.
    // They represent background processes that run forever like forwarding network
    // packets between tap devices. They never exit during normal enclave
    // execution and it is considered an error if they do.
    let mut background_tasks = start_background_tasks(networking_setup_result.tap_devices);

    let skip_def_cert_req = setup_result
        .env_vars
        .iter()
        .find(|(k, v)| k == "ENCLAVEOS_DISABLE_DEFAULT_CERTIFICATE" && !v.trim().is_empty())
        .is_some();

    let environment_setup_completed = Arc::new(Notify::new());
    let mut parent_stream = ParentStream::new(parent_port);

    // Setup auto cert renewal
    let parent_stream_cloned = parent_stream.clone();
    let environment_setup_completed_cloned = environment_setup_completed.clone();
    let app_config_id = setup_result.app_config.id.clone();
    let cert_settings = setup_result.enclave_manifest.user_config.certificate_config.clone();
    let is_debug = setup_result.enclave_manifest.is_debug;

    background_tasks.push(tokio::spawn(async move {
        auto_cert_renewals(parent_stream_cloned,
                          environment_setup_completed_cloned,
                          &app_config_id,
                          cert_settings,
                          is_debug,
                          skip_def_cert_req).await
    }));

    let enclave_exit_code = with_background_tasks!(background_tasks, {
        let parent_stream = parent_stream.clone();
        let mut parent_guard = parent_stream.lock().await;

        let mut certificate_info = setup_enclave_certifications(
            parent_guard.deref_mut(),
            &EmAppCSRApi {},
            &setup_result.app_config.id,
            &mut setup_result.enclave_manifest.user_config.certificate_config.clone(),
            Path::new(ENCLAVE_FS_OVERLAY_ROOT),
            skip_def_cert_req,
        )
        .await?;

        let fs_setup_config = FileSystemSetupConfig {
            enclave_manifest: &setup_result.enclave_manifest,
            env_vars: &setup_result.env_vars,
            cert_list: certificate_info.get_mut(0).map(|e| &mut e.certificate_result),
        };
        setup_file_system(parent_guard.deref_mut(), FileSystemSetupApiImpl {}, fs_setup_config).await?;

        for certificate in &mut certificate_info {
            write_certificate(
                certificate,
                Some(default_cert_dir()),
            )?;
        }

        let first_certificate = certificate_info.into_iter().next().map(|e| e.certificate_result);

        setup_app_configuration(&setup_result.app_config, first_certificate, &setup_result.enclave_manifest.ccm_backend_url)?;

        let log_conn_addrs = extract_enum_value!(parent_guard.deref_mut().read_lv().await?, SetupMessages::AppLogPort(addr) => addr)?;
        drop(parent_guard);

        // The environment for the user application is ready, signal this to background tasks
        // indicating that the file system, etc. is ready to be used
        environment_setup_completed.notify_waiters();

        let exit_status = start_and_await_user_program_return(setup_result, hostname, log_conn_addrs).await?;

        cleanup_fs().await?;

        Ok(exit_status)
    });

    signal_user_program_exit_status(&mut parent_stream, enclave_exit_code.clone()).await?;

    enclave_exit_code
}

fn enable_loopback_network_interface() -> Result<(), String> {
    use interfaces::Interface;

    let mut loopback_interface = match Interface::get_by_name("lo") {
        Ok(Some(result)) => result,
        Ok(None) => {
            warn!("Loopback interface is not present inside an enclave!");
            return Ok(());
        }
        Err(err) => return Err(format!("Failed accessing loopback network interface. {:?}", err)),
    };

    loopback_interface
        .set_up(true)
        .map_err(|err| format!("Failed to bring up loopback network interface. {:?}", err))?;

    debug!("Loopback network interface is up.");

    Ok(())
}

async fn startup(
    parent_port: &mut AsyncVsockStream,
    settings_path: &Path,
) -> Result<(EnclaveSetupResult, EnclaveNetworkingSetupResult), String> {
    let mut enclave_manifest = read_enclave_manifest(settings_path)?;

    debug!("Received enclave manifest {:?}", enclave_manifest);

    let mut runtime_env_vars = extract_enum_value!(parent_port.read_lv().await?, SetupMessages::EnvVariables(e) => e)?;
    let mut env_vars = convert_to_tuples(&enclave_manifest.env_vars)?;
    // TODO: Filter runtime env vars based on which variables can be overriden/restricted. This
    // configuration must be set at conversion time.
    env_vars.append(&mut runtime_env_vars);

    let mut extra_user_program_args =
        extract_enum_value!(parent_port.read_lv().await?, SetupMessages::ExtraUserProgramArguments(e) => e)?;

    if enclave_manifest.is_debug {
        let existing_arguments = &mut enclave_manifest.user_config.user_program_config.arguments;

        existing_arguments.append(&mut extra_user_program_args);

        debug!("Running user program with the args - {:?}", existing_arguments);
    }

    let mut app_config = extract_enum_value!(parent_port.read_lv().await?, SetupMessages::ApplicationConfig(e) => e)?;

    // Always enable server verification for appconfigs in non-debug enclaves
    if !enclave_manifest.is_debug {
        app_config.skip_server_verify = false;
    }

    let networking_setup_result = setup_tap_devices(parent_port).await?;

    Ok((
        EnclaveSetupResult {
            app_config,
            enclave_manifest,
            env_vars,
        },
        networking_setup_result,
    ))
}

fn convert_to_tuples(env_strs: &Vec<String>) -> Result<Vec<(String, String)>, String> {
    let mut res = vec![];
    for env in env_strs {
        let pair = env.split_once("=");
        match pair {
            None => {
                info!("Env string doesn't contain equal sign separating key value pair - {:?}", env);
            }
            Some(e) => {
                res.push((e.0.to_string(), e.1.to_string()));
            }
        }
    }
    Ok(res)
}

fn setup_app_configuration(
    app_config: &ApplicationConfiguration,
    certificate_info: Option<CertificateResult>,
    ccm_backend_url: &CcmBackendUrl,
) -> Result<(), String> {
    if let (Some(certificate_info), Some(id)) = (certificate_info, &app_config.id) {
        let api = EmAppApplicationConfiguration::new();
        let credentials = EmAppCredentials::new(certificate_info, app_config.skip_server_verify)?;

        info!("Setting up application configuration.");

        let app_config_id = Sha256Hash::try_from(id.as_str())
            .map_err(|err| format!("App config id is not a valid SHA-256 string. App config id is {}. Error {:?}", &id, err))?;

        setup_application_configuration(
            &credentials,
            ccm_backend_url,
            api,
            Path::new(ENCLAVE_FS_OVERLAY_ROOT),
            &app_config_id,
        )
    } else {
        Ok(())
    }
}

pub(crate) async fn setup_file_system<'a, Socket: AsyncWrite + AsyncRead + Unpin + Send, Api: FileSystemSetupApi<'a>>(
    parent_socket: &mut Socket,
    api: Api,
    setup_config: FileSystemSetupConfig<'a>,
) -> Result<(), String> {
    info!("Awaiting NBD config");
    let nbd_config = extract_enum_value!(parent_socket.read_lv().await?, SetupMessages::NBDConfiguration(e) => e)?;

    let space = api.setup(nbd_config, setup_config).await?;

    parent_socket.write_lv(&SetupMessages::EncryptedSpaceAvailable(space)).await?;

    Ok(())
}

pub struct FileSystemSetupConfig<'a> {
    pub enclave_manifest: &'a EnclaveManifest,

    pub env_vars: &'a [(String, String)],

    pub cert_list: Option<&'a mut CertificateResult>,
}

#[async_trait]
pub trait FileSystemSetupApi<'a> {
    async fn setup(&self, nbd_config: NBDConfiguration, arg: FileSystemSetupConfig<'a>) -> Result<usize, String>;
}

struct FileSystemSetupApiImpl {}
#[async_trait]
impl<'a> FileSystemSetupApi<'a> for FileSystemSetupApiImpl {
    async fn setup(&self, nbd_config: NBDConfiguration, arg: FileSystemSetupConfig<'a>) -> Result<usize, String> {
        let enclave_manifest = arg.enclave_manifest;
        let auth_cert = arg.cert_list;
        let dsm_url = (&arg.enclave_manifest.dsm_configuration.dsm_url).to_string();
        let fs_api_key = get_fs_api_key(arg.env_vars, arg.enclave_manifest.is_debug);

        for export in &nbd_config.exports {
            run_nbd_client(nbd_config.address, export.port, &export.name).await?;

            info!("Export {} is connected to NBD", export.name);
        }
        info!("All block files are connected and ready.");

        let verity_config = DMVerityConfig::new(
            enclave_manifest.file_system_config.hash_offset,
            enclave_manifest.file_system_config.root_hash.to_string(),
        );

        setup_dm_verity(&verity_config).await?;
        info!("Finished setup dm-verity.");

        create_overlay_dirs()?;
        info!("Created directories needed for overlay fs mount.");

        mount_read_only_file_system().await?;
        info!("Finished read only file system mount.");

        let conn_info = ClientConnectionInfo {
            fs_api_key,
            auth_cert,
            dsm_url
        };

        mount_read_write_file_system(enclave_manifest.enable_overlay_filesystem_persistence, conn_info).await?;
        info!("Finished read/write file system mount.");

        mount_overlay_fs().await?;
        info!("Mounted enclave root with overlay-fs.");

        let fs_mount_opts = fetch_fs_mount_options()?;
        mount_file_system_nodes(FILE_SYSTEM_NODES, fs_mount_opts).await?;

        copy_dns_file_to_mount()?;
        copy_startup_binary_to_mount(STARTUP_BINARY)?;

        create_fortanix_directories()?;

        info!("Finished file system mount.");

        get_available_encrypted_space().await
    }
}

async fn cleanup_fs() -> Result<(), String> {
    unmount_file_system_nodes(FILE_SYSTEM_NODES).await?;
    info!("Unmounted file system nodes.");

    unmount_overlay_fs().await?;
    info!("Unmounted overlay file system.");

    close_dm_crypt_device().await?;
    info!("Closed dm-crypt device.");

    close_dm_verity_volume().await?;
    info!("Closed dm-verity volume.");

    info!("Enclave cleanup has finished successfully.");
    Ok(())
}

async fn signal_user_program_exit_status(
    parent: &mut ParentStream,
    exit_status: Result<UserProgramExitStatus, String>,
) -> Result<(), String> {
    match parent.exchange_message(&SetupMessages::UserProgramExit(exit_status)).await? {
        SetupMessages::ExitEnclave => Ok(()),
        _ => Err(String::from("Expected exit response"))
    }
}

fn start_background_tasks(tap_devices: Vec<TapDeviceInfo>) -> FuturesUnordered<JoinHandle<Result<(), String>>> {
    let result = FuturesUnordered::new();

    for tap_device in tap_devices {
        let res = start_tap_loops(tap_device.tap, tap_device.vsock, tap_device.mtu);

        result.push(res.tap_to_vsock);
        result.push(res.vsock_to_tap);
    }

    result
}

async fn start_and_await_user_program_return(
    enclave_setup_result: EnclaveSetupResult,
    hostname: String,
    log_conn_addrs: Vec<AppLogPortInfo>,
) -> Result<UserProgramExitStatus, String> {
    let user_program = tokio::spawn(start_user_program(enclave_setup_result, hostname, log_conn_addrs));

    user_program
        .await
        .map_err(|err| format!("Join error in user program wait loop. {:?}", err))?
}

async fn connect_to_log_ports(log_addrs: Vec<AppLogPortInfo>) -> Result<Vec<(TcpStream, StreamType)>, String> {
    let mut res: Vec<(TcpStream, StreamType)> = vec![];
    for log_info in log_addrs {
        let stream = TcpStream::connect(log_info.sock_addr).await.map_err(|e| {
            format!(
                "Unable to connect to parent log server on socket {:?} : {:?}",
                log_info.sock_addr, e
            )
        })?;
        info!("Connected to parent on {:?} for stream {:?}", stream, log_info.stream_type);
        res.push((stream, log_info.stream_type));
    }
    Ok(res)
}

async fn forward_client_logs(
    enable_log_forwarding: bool,
    streams: Vec<(TcpStream, StreamType)>,
    client_program: &mut Child,
) -> Result<FuturesUnordered<JoinHandle<Result<(), String>>>, String> {
    let tasks = FuturesUnordered::new();
    if enable_log_forwarding {
        for (tcp_stream, stream_type) in streams {
            match stream_type {
                StreamType::Stdout => {
                    if let Some(handle) = client_program.stdout.take() {
                        tasks.push(send_logs(tcp_stream, handle).await);
                    }
                }
                StreamType::Stderr => {
                    if let Some(handle) = client_program.stderr.take() {
                        tasks.push(send_logs(tcp_stream, handle).await);
                    }
                }
            }
        }
    }
    Ok(tasks)
}

async fn send_logs<R: futures::io::AsyncRead + Unpin + Send + 'static>(
    out_stream: TcpStream,
    in_stream: R,
) -> JoinHandle<Result<(), String>> {
    let buffered_reader = BufReader::new(in_stream);
    let lines = buffered_reader.lines();
    tokio::spawn(write_lines_to_client(lines, out_stream))
}

async fn write_lines_to_client<R: futures::io::AsyncRead + Unpin + Send>(
    mut lines: Lines<BufReader<R>>,
    mut stream: TcpStream,
) -> Result<(), String> {
    while let Some(line) = lines.next().await {
        let line1 = line.unwrap_or_default();
        stream
            .write_all(line1.as_ref())
            .await
            .map_err(|e| format!("Unable to write to tcp sock : {:?}", e))?;
        stream
            .write("\n".as_ref())
            .await
            .map_err(|e| format!("Unable to print new line : {:?}", e))?;
    }
    Ok(())
}

async fn start_user_program(
    enclave_setup_result: EnclaveSetupResult,
    hostname: String,
    log_conn_addrs: Vec<AppLogPortInfo>,
) -> Result<UserProgramExitStatus, String> {
    let user_program = enclave_setup_result.enclave_manifest.user_config.user_program_config;
    let is_debug_shell = enclave_setup_result
        .env_vars
        .contains(&(DEBUG_SHELL_ENV_VAR.to_string(), "true".to_string()));

    let enable_log_forwarding = !log_conn_addrs.is_empty();

    let mut client_command = if !is_debug_shell {
        let mut client_command = Command::new("chroot");

        client_command.args([
            ENCLAVE_FS_OVERLAY_ROOT,
            STARTUP_BINARY,
            &user_program.working_dir,
            &user_program.user,
            &user_program.group,
            &hostname,
            &user_program.entry_point,
        ]);

        client_command.args(user_program.arguments.clone());
        if enable_log_forwarding {
            client_command.stdout(Stdio::piped());
            client_command.stderr(Stdio::piped());
        }

        client_command
    } else {
        // We have to recreate /run/sshd because it is setup as a `tmpfs` by a nitro kernel.
        if is_debug_shell {
            fs::create_dir_all("/run/sshd").map_err(|err| format!("Failed creating dir /run/sshd. {:?}", err))?;
        }

        let mut client_command = Command::new(user_program.entry_point.clone());

        client_command.args(user_program.arguments.clone());

        client_command
    };

    info!("Setting the following env vars {:?}", enclave_setup_result.env_vars);
    client_command.envs(enclave_setup_result.env_vars);

    let streams = connect_to_log_ports(log_conn_addrs).await?;

    let mut client_program = client_command
        .spawn()
        .map_err(|err| format!("Failed to start client program!. {:?}", err))?;

    let tasks = forward_client_logs(enable_log_forwarding, streams, &mut client_program).await?;

    info!("launching client program");
    let output = client_program
        .output()
        .await
        .map_err(|err| format!("Error while waiting for client program to finish: {:?}", err))?;

    info!("client program returns result status >> {:?}", output.status);
    let result = if let Some(code) = output.status.code() {
        UserProgramExitStatus::ExitCode(code)
    } else {
        UserProgramExitStatus::TerminatedBySignal
    };

    cleanup_tokio_tasks(tasks)?;

    Ok(result)
}

async fn setup_tap_devices(vsock: &mut AsyncVsockStream) -> Result<EnclaveNetworkingSetupResult, String> {
    let mut result = setup_enclave_networking(vsock).await?;
    info!("Finished networking setup.");

    let file_system_tap = {
        let configuration = extract_enum_value!(vsock.read_lv().await?, SetupMessages::PrivateNetworkDeviceSettings(e) => e)?;

        setup_file_system_tap_device(configuration).await?
    };

    result.tap_devices.push(file_system_tap);
    info!("Finished file system tap device setup.");

    Ok(result)
}

async fn setup_file_system_tap_device(configuration: PrivateNetworkDeviceSettings) -> Result<TapDeviceInfo, String> {
    let tap = create_async_tap_device(&tap_device_config(
        &configuration.l3_address,
        &configuration.name,
        configuration.mtu,
    ))?;
    let fs_vsock = connect_to_parent_async(configuration.vsock_port_number).await?;

    info!("FS Device {} is connected and ready.", configuration.vsock_port_number);

    Ok(TapDeviceInfo {
        vsock: fs_vsock,
        tap,
        mtu: configuration.mtu,
    })
}

struct EnclaveSetupResult {
    app_config: ApplicationConfiguration,

    enclave_manifest: EnclaveManifest,

    env_vars: Vec<(String, String)>,
}

struct TapDeviceInfo {
    vsock: AsyncVsockStream,

    tap: AsyncDevice,

    mtu: u32,
}

struct EnclaveNetworkingSetupResult {
    hostname: String,

    tap_devices: Vec<TapDeviceInfo>,
}

async fn setup_enclave_networking(parent_port: &mut AsyncVsockStream) -> Result<EnclaveNetworkingSetupResult, String> {
    let netlink = Netlink::new();

    let device_settings_list = extract_enum_value!(parent_port.read_lv().await?, SetupMessages::NetworkDeviceSettings(s) => s)?;

    let mut tap_devices: Vec<TapDeviceInfo> = Vec::new();

    for device_settings in &device_settings_list {
        let tap = setup_network_device(device_settings, &netlink).await?;
        info!("Trying to connect on port {}", device_settings.vsock_port_number);
        let vsock = connect_to_parent_async(device_settings.vsock_port_number).await?;

        info!("Device {} is connected and ready.", device_settings.vsock_port_number);

        tap_devices.push(TapDeviceInfo {
            vsock,
            tap,
            mtu: device_settings.mtu,
        });
    }

    let global_settings = extract_enum_value!(parent_port.read_lv().await?, SetupMessages::GlobalNetworkSettings(s) => s)?;

    fs::create_dir("/run/resolvconf").map_err(|err| format!("Failed creating /run/resolvconf. {:?}", err))?;

    for file in global_settings.global_settings_list {
        write_to_file(Path::new(&file.path), &file.data, &file.path)?;

        debug!("Successfully created {} inside an enclave.", &file.path);
    }
    debug!("Enclave global network settings files have been created.");

    enable_loopback_network_interface()?;

    Ok(EnclaveNetworkingSetupResult {
        hostname: global_settings.hostname,
        tap_devices,
    })
}

async fn setup_network_device(parent_settings: &NetworkDeviceSettings, netlink: &Netlink) -> Result<AsyncDevice, String> {
    let tap_device = create_async_tap_device(&tun::Configuration::from(parent_settings))?;

    let tap_index =
        if_nametoindex(tap_device.get_ref().name()).map_err(|err| format!("Cannot find index for tap device {:?}", err))?;

    info!(
        "Setting up device with index {} and settings {:?}.",
        tap_index, parent_settings
    );

    netlink
        .set_link_for_device(tap_index, &parent_settings.self_l2_address)
        .await?;

    // It is required that we add routes first and then the gateway
    // Kernel allows us to add the gateway only if there is a reachable route for
    // gateway's address in the routing table. Without said route(s) the kernel
    // will return NETWORK_UNREACHABLE status code for our add_gateway function.
    for route in &parent_settings.routes {
        match netlink.add_route_for_device(tap_index, route).await {
            Err(e) => {
                log::warn!("Unable to add route {:?}", e);
            }
            _ => {
                info!("Added route {:?}.", route);
            }
        }
    }

    if let Some(gateway) = &parent_settings.gateway {
        netlink.add_gateway(gateway).await?;
        debug!("Gateway {:?} is set.", parent_settings.gateway);
    }

    // It might be the case when parent's neighbour resolution depends on a static
    // manually inserted ARP entries and not on protocol's capability to
    // automatically learn neighbours. In this case we have to manually copy
    // those entries from parent as it becomes the only way for the enclave to know
    // it's neighbours.
    for arp_entry in &parent_settings.static_arp_entries {
        netlink.add_neighbour_for_device(tap_index, arp_entry).await?;

        debug!("ARP entry {:?} is set.", arp_entry);
    }

    Ok(tap_device)
}

pub(crate) async fn setup_enclave_certifications<Socket: AsyncWrite + AsyncRead + Unpin + Send, Api: CSRApi>(
    vsock: &mut Socket,
    csr_api: &Api,
    app_config_id: &Option<String>,
    cert_settings: &mut Vec<CertificateConfig>,
    fs_root: &Path,
    skip_def_cert_req: bool,
) -> Result<Vec<CertificateWithPath>, String> {
    let mut certs = Vec::new();

    if !skip_def_cert_req && cert_settings.is_empty() {
        cert_settings.push(default_certificate());
    }

    // Zero or more certificate requests.
    for cert_config in cert_settings {
        certs.push(setup_enclave_certification(vsock, csr_api, app_config_id, cert_config, fs_root).await?);
    }

    vsock.write_lv(&SetupMessages::NoMoreCertificates).await?;

    info!("Finished requesting {} certificates.", certs.len());

    Ok(certs)
}

pub(crate) async fn setup_enclave_certification<Socket: AsyncWrite + AsyncRead + Unpin + Send, Api: CSRApi>(
    vsock: &mut Socket,
    csr_api: &Api,
    app_config_id: &Option<String>,
    cert_config: &CertificateConfig,
    fs_root: &Path,
) -> Result<CertificateWithPath, String> {
    if let Some(kp) = &cert_config.key_param {
        let key_size = kp.as_u64().unwrap_or(DEFAULT_CERT_RSA_KEY_SIZE.into());
        let mut key = create_signer_key(key_size as u32)?;
        let csr = csr_api.get_remote_attestation_csr(cert_config, app_config_id, &mut key)?;
        let certificate = request_certificate(vsock, csr).await?;

        Ok(CertificateWithPath::new(
            CertificateResult { certificate, key },
            cert_config,
            fs_root,
        ))
    } else {
        Err(format!("key param not specified for cert config {:?}", cert_config))
    }
}

async fn connect_to_parent_async(port: u32) -> Result<AsyncVsockStream, String> {
    let result = AsyncVsockStream::connect(VSOCK_PARENT_CID, port)
        .await
        .map_err(|err| format!("Failed to connect to parent: {:?}", err))?;

    info!("Connected to parent.");

    Ok(result)
}

fn read_enclave_manifest(path: &Path) -> Result<EnclaveManifest, String> {
    let settings_raw = fs::read_to_string(path).map_err(|err| format!("Failed to read enclave manifest file. {:?}", err))?;

    serde_json::from_str(&settings_raw).map_err(|err| format!("Failed to deserialize enclave manifest. {:?}", err))
}

pub(crate) fn write_to_file<C: AsRef<[u8]> + ?Sized>(path: &Path, data: &C, entity_name: &str) -> Result<(), String> {
    fs::write(path, data).map_err(|err| format!("Failed to write {} into file {}. {:?}", path.display(), entity_name, err))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use api_model::{converter::{DsmConfiguration}, enclave::{CcmBackendUrl, EnclaveManifest, FileSystemConfig, User, UserConfig, UserProgramConfig, WorkingDir}};
    use async_trait::async_trait;
    use shared::models::NBDConfiguration;
    use shared::socket::InMemorySocket;
    use tokio::runtime::Runtime;

    use crate::enclave::{FileSystemSetupApi, FileSystemSetupConfig};

    struct MockFileSystemApi {}
    #[async_trait]
    impl<'a> FileSystemSetupApi<'a> for MockFileSystemApi {
        async fn setup(&self, _nbd_config: NBDConfiguration, _arg: FileSystemSetupConfig<'a>) -> Result<usize, String> {
            Ok(777)
        }
    }

    async fn parent(mut parent_socket: InMemorySocket) -> Result<(), String> {
        parent_lib::setup_file_system(&mut parent_socket, IpAddr::V4(Ipv4Addr::LOCALHOST)).await
    }

    async fn enclave(mut enclave_socket: InMemorySocket) -> Result<(), String> {
        let setup_config = FileSystemSetupConfig {
            enclave_manifest: &EnclaveManifest {
                user_config: UserConfig {
                    user_program_config: UserProgramConfig {
                        entry_point: "".to_string(),
                        arguments: vec![],
                        working_dir: WorkingDir::from(""),
                        user: User::from(""),
                        group: User::from(""),
                    },
                    certificate_config: vec![],
                },
                file_system_config: FileSystemConfig {
                    root_hash: "".to_string(),
                    hash_offset: 0,
                },
                is_debug: false,
                env_vars: vec![],
                enable_overlay_filesystem_persistence: false,
                ccm_backend_url: CcmBackendUrl {
                    host: "".to_string(),
                    port: 0,
                },
                dsm_configuration: DsmConfiguration {
                    dsm_url: "".to_string()
                },
            },
            env_vars: &[],
            cert_list: None,
        };

        crate::enclave::setup_file_system(&mut enclave_socket, MockFileSystemApi {}, setup_config).await
    }

    #[test]
    fn setup_enclave_file_system_correct_pass() {
        let (enclave_socket, parent_socket) = InMemorySocket::socket_pair();
        let rt = Runtime::new().expect("Tokio runtime OK");

        rt.block_on(async move {
            let a = tokio::spawn(parent(parent_socket));
            let b = tokio::spawn(enclave(enclave_socket));

            let (a_result, b_result) = tokio::join!(a, b);

            assert!(a_result.is_ok());
            assert!(b_result.is_ok());
        });
    }
}

/// If it is a debug enclave, search for and return the FS_API_KEY. For a regular,
/// (non-debug) enclave, do not allow usage of an api key
fn get_fs_api_key(env_vars: &[(String, String)], is_debug: bool) -> Option<String> {
    if is_debug {
        return env_vars
        .iter()
        .find_map(|e| if e.0 == "FS_API_KEY" { Some(e.1.clone()) } else { None });
    }
    None
}
