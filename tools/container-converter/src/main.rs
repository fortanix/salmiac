/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use clap::{App, AppSettings, Arg, ArgMatches};
use env_logger;
use std::fs;

#[cfg(platform = "nitro")]
#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let console_arguments = console_arguments(
        "Converts user docker container to be able to run in AWS Nitro environment",
    );

    let request_file_path = console_arguments
        .value_of("request-file")
        .expect("Request file must be provided");

    let request_file = fs::read_to_string(request_file_path)
        .map_err(|err| format!("Failed reading request file. {:?}", err))?;

    container_converter::nitro::process_request(&request_file).await
}

#[cfg(platform = "snp")]
#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let console_arguments = console_arguments(
        "Converts user docker container to be able to run in AMD SNP environment",
    );

    let request_file_path = console_arguments
        .value_of("request-file")
        .expect("Request file must be provided");

    let request_file = fs::read_to_string(request_file_path)
        .map_err(|err| format!("Failed reading request file. {:?}", err))?;

    container_converter::snp::process_request(&request_file).await
}

fn console_arguments<'a>(platform: &'static str) -> ArgMatches<'a> {
    App::new("Container converter")
        .about(platform)
        .setting(AppSettings::DisableVersion)
        .arg(
            Arg::with_name("request-file")
                .help("Path to a file that contains conversion request")
                .long("request-file")
                .takes_value(true)
                .required(true),
        )
        .get_matches()
}
