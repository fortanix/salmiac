/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod network;
mod packet_capture;
mod parent;

use std::process;

use clap::{App, AppSettings, Arg, ArgMatches};
use log::{error, info, warn};
use model_types::ByteUnit;
use shared::models::UserProgramExitStatus;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();
    let parent_args = ParentConsoleArguments::new(&matches);

    match parent::run(parent_args).await {
        Ok(UserProgramExitStatus::ExitCode(code)) => {
            info!("User program exits with code: {}", code);
            process::exit(code)
        }
        Ok(UserProgramExitStatus::TerminatedBySignal) => {
            info!("User program is terminated by signal.");
            process::exit(-1);
        }
        Err(e) => {
            error!("Parent exits with failure: {}", e);
            process::exit(-1);
        }
    }
}

struct ParentConsoleArguments {
    pub rw_block_file_size: ByteUnit,

    pub enclave_extra_args: Vec<String>,
}

impl ParentConsoleArguments {
    // 256MB converted to bytes
    const RW_BLOCK_FILE_DEFAULT_SIZE: u64 = 256 * 1024 * 1024;

    fn default_rw_block_file_size() -> ByteUnit {
        ByteUnit::new(ParentConsoleArguments::RW_BLOCK_FILE_DEFAULT_SIZE)
    }

    fn new(matches: &ArgMatches) -> Self {
        let rw_storage_size = std::env::vars()
            .find(|e| e.0 == "RW_STORAGE_SIZE")
            .map(|e| ByteUnit::from_str(&e.1));

        let rw_block_file_size = match rw_storage_size {
            Some(Ok(result)) => result,
            Some(Err(err)) => {
                warn!(
                    "Cannot parse RW_STORAGE_SIZE.{:?}. Setting read/write block file size to a default value of {}",
                    err,
                    ParentConsoleArguments::RW_BLOCK_FILE_DEFAULT_SIZE
                );
                ParentConsoleArguments::default_rw_block_file_size()
            }
            None => {
                warn!(
                    "RW_STORAGE_SIZE is not present. Setting read/write block file size to a default value of {}",
                    ParentConsoleArguments::RW_BLOCK_FILE_DEFAULT_SIZE
                );
                ParentConsoleArguments::default_rw_block_file_size()
            }
        };

        let enclave_extra_args = matches
            .values_of("unknown")
            .unwrap_or_default()
            .into_iter()
            .map(|e| e.to_string())
            .collect();
        info!("enclave_extra_args is {:?}", enclave_extra_args);

        Self {
            rw_block_file_size,
            enclave_extra_args,
        }
    }
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    let result = App::new("Vsock proxy")
        .about("Vsock proxy")
        .setting(AppSettings::AllowExternalSubcommands)
        .setting(AppSettings::AllowLeadingHyphen)
        .setting(AppSettings::DisableVersion)
        .setting(AppSettings::DisableHelpFlags)
        // Together with settings `AppSettings::AllowExternalSubcommands` and `AppSettings::AllowLeadingHyphen`
        // this `arg()` will capture all not defined arguments
        .arg(Arg::with_name("unknown").multiple(true).allow_hyphen_values(true));

    result.get_matches()
}
