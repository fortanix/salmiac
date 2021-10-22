mod parent;
mod packet_capture;

use clap::{ArgMatches, App, AppSettings, Arg};
use log::error;

use shared::{parse_console_argument, NumArg};

use std::process;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    let vsock_port = parse_console_argument::<u32>(&matches, "vsock-port");

    if let Err(e) = parent::run(vsock_port).await {
        error!("Parent exits with failure: {}", e);
        process::exit(1);
    }

    Ok(())
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
                .required(true)
        );

    result.get_matches()
}
