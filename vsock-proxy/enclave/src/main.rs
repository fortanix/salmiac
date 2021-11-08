mod enclave;

use clap::{ArgMatches, App, AppSettings, Arg};
use log::{error, info};

use shared::{parse_console_argument, NumArg, UserProgramExitStatus};

use std::process;
use std::path::Path;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    let vsock_port = parse_console_argument::<u32>(&matches, "vsock-port");
    let settings_path = matches.value_of("settings-path")
        .map(|e| Path::new(e))
        .expect("Path to a settings file must be provided");

    match enclave::run(vsock_port, &settings_path).await {
        Ok(UserProgramExitStatus::ExitCode(code)) => {
            info!("User program exits with code: {}", code);
            process::exit(code)
        }
        Ok(UserProgramExitStatus::TerminatedBySignal) => {
            info!("User program is terminated by signal.");
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
