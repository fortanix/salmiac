pub mod parent;
pub mod enclave;

use clap::{
    App,
    AppSettings,
    Arg,
    SubCommand,
    ArgMatches
};

use std::str::FromStr;
use std::fmt::Display;
use std::net::IpAddr;

pub fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Vsock proxy")
        .about("Vsock proxy")
        .setting(AppSettings::DisableVersion)
        .subcommand(
            SubCommand::with_name("parent")
                .about("Vsock proxy that runs inside the parent")
                .arg(
                    Arg::with_name("vsock-port")
                        .long("vsock-port")
                        .help("vsock port")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("remote-port")
                        .long("remote-port")
                        .help("remote port")
                        .takes_value(true)
                        .required(true),
                )
        )
        .subcommand(
            SubCommand::with_name("client")
                .about("Client that sends messages to to EC2")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .help("EC2 address")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("remote-port")
                        .long("remote-port")
                        .help("remote port")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("udp")
                        .help("protocol name")
                        .takes_value(false)
                        .required(false),
                )
        )
        .subcommand(
            SubCommand::with_name("enclave")
                .about("Vsock-proxy that runs inside the enclave")
                .arg(
                    Arg::with_name("vsock-port")
                        .long("vsock-port")
                        .help("vsock port")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("remote-port")
                        .long("remote-port")
                        .help("remote port")
                        .takes_value(true)
                        .required(true),
                )
        )
        .subcommand(
            SubCommand::with_name("test")
                .about("Test program that represents the client running inside the enclave")
                .arg(
                    Arg::with_name("remote-port")
                        .long("remote-port")
                        .help("remote port")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("udp")
                        .help("protocol name")
                        .takes_value(false)
                        .required(false),
                )
        )
        .get_matches()
}

pub fn parse_console_argument<T : FromStr + Display>(args: &ArgMatches, name: &str) -> Result<T, String> {
    args.value_of(name)
        .map(|e| e.parse::<T>())
        .expect(format!("{} must be specified", name).as_str())
        .map_err(|_err| format!("Cannot parse console argument {}", name))
}

pub fn address_argument(args: &ArgMatches) -> Result<IpAddr, String> {
    args.value_of("address")
        .map(|e| e.parse::<IpAddr>())
        .expect("address must be specified")
        .map_err(|err| format!("Cannot parse address {:?}", err))
}