#![feature(lazy_cell)]
/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use clap::{App, AppSettings, Arg, ArgMatches};
use container_converter::process_request;
use std::{fs, sync::LazyLock};

#[cfg(platform = "nitro")]
use container_converter::nitro as platform;
#[cfg(platform = "simulator")]
use container_converter::simulator as platform;
#[cfg(platform = "snp")]
use container_converter::snp as platform;
#[cfg(platform = "tdx")]
use container_converter::tdx as platform;

static ABOUT: LazyLock<String> = LazyLock::new(|| {
    format!(
        "Converts user docker container to be able to run in {} environment",
        platform::NAME
    )
});

const REQUEST_FILE_PARAM_NAME: &str = "request-file";
const RESPONSE_FILE_PARAM_NAME: &str = "response-file";

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let console_arguments = console_arguments(&ABOUT);

    let request_file_path = console_arguments
        .value_of(REQUEST_FILE_PARAM_NAME)
        .expect("Request file must be provided");

    let request_file = fs::read_to_string(request_file_path)
        .map_err(|err| format!("Failed reading request file: {:?}", err))?;

    let response_serialized = process_request(&request_file).await?;

    if let Some(response_file) = console_arguments.value_of(RESPONSE_FILE_PARAM_NAME) {
        fs::write(response_file, response_serialized)
            .map_err(|err| format!("Failed writing response file: {:?}", err))?;
    }

    Ok(())
}

fn console_arguments<'a>(platform: &'static str) -> ArgMatches<'a> {
    App::new("Container converter")
        .about(platform)
        .setting(AppSettings::DisableVersion)
        .arg(
            Arg::with_name(REQUEST_FILE_PARAM_NAME)
                .help("Path to a file that contains conversion request")
                .long(REQUEST_FILE_PARAM_NAME)
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name(RESPONSE_FILE_PARAM_NAME)
                .help("Path to a file that contains conversion response, if successful")
                .long(RESPONSE_FILE_PARAM_NAME)
                .takes_value(true)
                .required(false),
        )
        .get_matches()
}
