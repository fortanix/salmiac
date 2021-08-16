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

pub const VSOCK_PARENT_CID: u32 = 3; // From AWS Nitro documentation.

pub fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Vsock proxy")
        .about("Vsock proxy")
        .setting(AppSettings::DisableVersion)
        .subcommand(
            parent_sub_command()
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
        )
        .get_matches()
}

fn parent_sub_command<'a, 'b>() -> App<'a, 'b> {
    let result = SubCommand::with_name("parent")
        .about("Vsock proxy that runs inside the parent")
        .arg(
            Arg::with_name("vsock-port")
                .long("vsock-port")
                .help("vsock port")
                .takes_value(true)
                .required(true)
        );

    if cfg!(debug_assertions) {
        result.arg(
            Arg::with_name("remote-port")
                .long("remote-port")
                .help("remote port")
                .takes_value(true)
                .required(false)
        )
    } else {
        result
    }
}

pub fn parse_console_argument<T : FromStr + Display>(args: &ArgMatches, name: &str) -> Result<T, String> {
    parse_optional_console_argument(args, name).expect(format!("{} must be specified", name).as_str())
}

pub fn parse_optional_console_argument<T : FromStr + Display>(args: &ArgMatches, name: &str) -> Option<Result<T, String>> {
    args.value_of(name).map(|e| parse_argument(e, name))
}

fn parse_argument<T : FromStr + Display>(_str: &str, name : &str) -> Result<T, String> {
    _str.parse::<T>().map_err(|_err| format!("Cannot parse console argument {}", name))
}