mod network;
mod packet_capture;
mod parent;

use clap::{App, AppSettings, Arg, ArgMatches};
use log::{error, info};

use shared::{parse_console_argument, NumArg, UserProgramExitStatus};

use std::process;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), String> {
    env_logger::init();

    let matches =  console_arguments();

    let vsock_port = parse_console_argument::<u32>(&matches, "vsock-port");

    match parent::run(vsock_port).await {
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
        );

    result.get_matches()
}
