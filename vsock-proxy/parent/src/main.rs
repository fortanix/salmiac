mod network;
mod packet_capture;
mod parent;

use clap::{App, AppSettings, Arg, ArgMatches};
use log::{error, info};
use shared::models::UserProgramExitStatus;
use std::process;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();
    let enclave_extra_args = matches
        .values_of("unknown")
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.to_string())
        .collect();
    info!("enclave_extra_args is {:?}", enclave_extra_args);
    match parent::run(enclave_extra_args).await {
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
