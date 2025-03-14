/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use clap::{App, AppSettings, Arg, ArgMatches};
use env_logger;
use log::error;

use api_model::converter::NitroEnclavesConversionRequest;

use std::fs;

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let console_arguments = console_arguments();

    let request_file_path = console_arguments
        .value_of("request-file")
        .expect("Request file must be provided");

    let request_file =
        fs::read_to_string(request_file_path).map_err(|err| format!("Failed reading request file. {:?}", err))?;

    let request = serde_json::from_str::<NitroEnclavesConversionRequest>(&request_file)
        .map_err(|err| format!("Failed deserializing conversion request. {:?}", err))?;

    match container_converter::run(request).await {
        Ok(response) => {
            let response_serialized = serde_json::to_string(&response)
                .map_err(|err| format!("Failed serializing conversion request. {:?}", err))?;

            println!("Successful nitro conversion: {:?}", response_serialized);
            Ok(())
        }
        Err(err) => {
            error!("Converter exited with error: {}", err.message);
            Err(err.message)
        }
    }
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Container converter")
        .about("Converts user docker container to be able to run in AWS Nitro environment")
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
