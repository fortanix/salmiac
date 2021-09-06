mod enclave;

use shared::{parse_console_argument, NumArg};
use clap::{ArgMatches, App, AppSettings, Arg};

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    let vsock_port = parse_console_argument::<u32>(&matches, "vsock-port");

    enclave::run(vsock_port).await?;

    Ok(())
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
        .get_matches()
}
