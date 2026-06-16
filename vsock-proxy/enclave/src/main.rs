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
use shared::{NumArg, parse_console_argument};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    let vsock_port = parse_console_argument::<u32>(&matches, "vsock-port");

    if matches.is_present("attestation-test") {
        #[cfg(any(platform = "snp", platform = "tdx"))]
        return enclave::run_attestation_client_only(vsock_port).await;

        #[cfg(not(all(platform = "snp", platform = "tdx")))]
        return Err("attestation-test functionality is not valid for nitro build".to_string());
    } else {
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
}

const fn platform_type() -> &'static str {
    #[cfg(platform = "snp")]
    return "snp";
    #[cfg(platform = "tdx")]
    return "tdx";
    #[cfg(platform = "nitro")]
    return "nitro";
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    let app = App::new(format!("Vsock proxy enclave ({})", platform_type()))
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
                .required_unless("attestation-test"),
        );

    #[cfg(any(platform = "snp", platform = "tdx"))]
    app.arg(
        Arg::with_name("attestation-test")
            .long("attestation-test")
            .help("Run Vsock proxy executable for testing the attestation")
            .takes_value(false),
    );

    app.get_matches()
}
