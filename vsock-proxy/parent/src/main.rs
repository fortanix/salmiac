mod parent;
mod packet_capture;

use clap::{ArgMatches, App, AppSettings, Arg};
use log::error;

use shared::{parse_console_argument, parse_optional_console_argument, NumArg};

use std::process;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    let vsock_port = parse_console_argument::<u32>(&matches, "vsock-port");
    let remote_port = if cfg!(debug_assertions) {
        parse_optional_console_argument::<u32>(&matches, "remote-port")
    } else {
        None
    };

    if let Err(e) = parent::run(vsock_port, remote_port).await {
        error!("Parent returns with failure: {}", e);
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

    let debug_result = if cfg!(debug_assertions) {
        result.arg(
            Arg::with_name("remote-port")
                .long("remote-port")
                .help("remote port")
                .validator(u32::validate_arg)
                .takes_value(true)
                .required(false)
        )
    } else {
        result
    };

    debug_result.get_matches()
}
