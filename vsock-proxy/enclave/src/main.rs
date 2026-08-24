/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod app_configuration;
mod certificate;
mod enclave;
mod file_system;
mod platform;

use std::path::Path;
use std::process;

use clap::{App, AppSettings, Arg, ArgMatches};
use log::{debug, error};
use shared::models::UserProgramExitStatus;
use shared::NumArg;

#[cfg(any(platform = "snp", platform = "tdx", platform = "simulator"))]
fn obtain_vsock_cid() -> Result<u32, String> {
    mod constants {
        pub const VSOCK_DEVICE_PATH: &str = "/dev/vsock";
        pub const IOCTL_VM_SOCKETS_GET_LOCAL_CID: usize = 0x7b9;
    }

    // linux/include/uapi/linux/vm_sockets.h
    nix::ioctl_read_bad!(
        get_local_cid,
        constants::IOCTL_VM_SOCKETS_GET_LOCAL_CID,
        u32
    );

    use nix::{fcntl::OFlag, sys::stat::Mode};

    let fd = nix::fcntl::open(constants::VSOCK_DEVICE_PATH, OFlag::O_RDONLY, Mode::empty())
        .map_err(|e| format!("unable to open vsock device: {e}"))?;

    let mut cid: u32 = 0;
    unsafe { get_local_cid(fd, &mut cid).map_err(|e| format!("unable to get local cid: {e}"))? };

    debug!("Obtained CID: {cid}");

    Ok(cid as u32)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    #[cfg(platform = "nitro")]
    let vsock_port = shared::VSOCK_PARENT_PORT;

    #[cfg(any(platform = "snp", platform = "tdx", platform = "simulator"))]
    let vsock_port = obtain_vsock_cid()?;

    let settings_path = matches
        .value_of("settings-path")
        .map(|e| Path::new(e))
        .expect("Path to a settings file must be provided");

    match enclave::run(vsock_port, &settings_path).await {
        Ok(UserProgramExitStatus::ExitCode(code)) => {
            debug!("User program exits with code: {}", code);
            process::exit(code)
        }
        Ok(UserProgramExitStatus::TerminatedBySignal) => {
            debug!("User program is terminated by signal.");
            process::exit(-1);
        }
        Err(e) => {
            error!("Enclave exits with failure: {}", e);

            process::exit(-1);
        }
    }
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Vsock proxy enclave")
        .about("Vsock proxy")
        .setting(AppSettings::DisableVersion)
        .arg(
            Arg::with_name("vsock-port")
                .long("vsock-port")
                .help("vsock port")
                .validator(u32::validate_arg)
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("settings-path")
                .long("settings-path")
                .help("Path to a settings file")
                .takes_value(true)
                .required(true),
        )
        .get_matches()
}
