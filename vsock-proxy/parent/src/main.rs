mod network;
mod packet_capture;
mod parent;

use clap::{App, AppSettings, Arg, ArgMatches};
use log::{error, info};

use shared::{parse_console_argument, NumArg, UserProgramExitStatus};

use std::process;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), String> {
    // turn on logging only for this project to prevent 3rd party
    // crates spamming their logs into the console
    std::env::set_var("RUST_LOG", "parent");
    env_logger::init();

    let matches = console_arguments();

    let vsock_port = parse_console_argument::<u32>(&matches, "vsock-port");

    let use_file_system = if matches.is_present("use-file-system") {
        true
    } else {
        false
    };

    match parent::run(vsock_port, use_file_system).await {
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
            Arg::with_name("use-file-system")
                .long("use-file-system")
                .takes_value(false)
                .required(false),
        );

    result.get_matches()
}
