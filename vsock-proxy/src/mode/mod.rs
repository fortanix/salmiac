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
use std::num::ParseIntError;
use std::borrow::Borrow;

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
                        .validator(u32::validate_arg)
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
                .validator(u32::validate_arg)
                .takes_value(true)
                .required(true)
        );

    if cfg!(debug_assertions) {
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
    }
}

pub fn parse_console_argument<T : FromStr + Display + NumArg>(args: &ArgMatches, name: &str) -> Result<T, String> {
    parse_optional_console_argument(args, name).expect(format!("{} must be specified", name).as_str())
}

pub fn parse_optional_console_argument<T : FromStr + Display + NumArg>(args: &ArgMatches, name: &str) -> Option<Result<T, String>> {
    args.value_of(name).map(|e| parse_num(e).map_err(|_err| format!("Cannot parse console argument {}", name)))
}

pub trait NumArg: Copy {
    fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError>;

    fn parse_arg<S: Borrow<str>>(s: S) -> Self {
        parse_num(s).unwrap()
    }

    fn validate_arg(s: String) -> Result<(), String> {
        match parse_num::<Self, _>(s) {
            Ok(_) => Ok(()),
            Err(_) => Err(String::from("the value must be numeric")),
        }
    }
}

fn parse_num<T: NumArg, S: Borrow<str>>(s: S) -> Result<T, ParseIntError> {
    let s = s.borrow();
    if s.starts_with("0x") {
        T::from_str_radix(&s[2..], 16)
    } else {
        T::from_str_radix(s, 10)
    }
}

macro_rules! impl_numarg(
($($t:ty),+) => ($(
    impl NumArg for $t {
        fn from_str_radix(src: &str, radix: u32) -> Result<Self, ParseIntError> {
            Self::from_str_radix(src,radix)
        }
    }
)+););
impl_numarg!(u32);