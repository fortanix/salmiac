mod app_configuration;
mod certificate;
mod enclave;
mod file_system;

use clap::{App, AppSettings, Arg, ArgMatches};
use log::{debug, error};

use shared::{parse_console_argument, NumArg, UserProgramExitStatus};

use std::path::Path;
use std::process;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), String> {
    // turn on logging only for this project to prevent 3rd party
    // crates spamming their logs into the console
    std::env::set_var("RUST_LOG", "enclave");
    env_logger::init();

    let matches = console_arguments();

    let vsock_port = parse_console_argument::<u32>(&matches, "vsock-port");
    let settings_path = matches
        .value_of("settings-path")
        .map(|e| Path::new(e))
        .expect("Path to a settings file must be provided");

    let use_file_system = if matches.is_present("use-file-system") {
        true
    } else {
        false
    };

    match enclave::run(vsock_port, &settings_path, use_file_system).await {
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
        .arg(
            Arg::with_name("use-file-system")
                .long("use-file-system")
                .takes_value(false)
                .required(false),
        )
        .get_matches()
}
