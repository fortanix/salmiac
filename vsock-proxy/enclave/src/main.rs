mod app_configuration;
mod certificate;
mod enclave;
mod file_system;

use clap::{App, AppSettings, Arg, ArgMatches};
use log::{debug};

use shared::{parse_console_argument, NumArg, UserProgramExitStatus};

use std::path::Path;
use std::process;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    let vsock_port = parse_console_argument::<u32>(&matches, "vsock-port");
    let settings_path = matches
        .value_of("settings-path")
        .map(|e| Path::new(e))
        .expect("Path to a settings file must be provided");

    let (vsock, _background_tasks, user_program) = enclave::startup(vsock_port, &settings_path).await?;

    let exit_status = enclave::await_user_program_return(user_program).await?;

    enclave::cleanup().await?;

    enclave::send_user_program_exit_status(vsock, exit_status.clone()).await?;

    match exit_status {
        UserProgramExitStatus::ExitCode(code) => {
            debug!("User program exits with code: {}", code);
            process::exit(code)
        }
        _ => {
            debug!("User program is terminated by signal.");
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
