pub mod device;
pub mod netlink;
pub mod socket;

use clap::{
    ArgMatches
};
use serde::{
    Serialize,
    Deserialize
};
use tokio::task::JoinError;

use std::num::ParseIntError;
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const ETHERNET_HEADER_SIZE: u32 = 14;

pub fn vec_to_ip4(vec : &[u8]) -> Result<Ipv4Addr, String> {
    let as_array = <[u8; 4]>::try_from(&vec[..])
        .map_err(|err| format!("Cannot convert vec to array {:?}", err))?;

    Ok(Ipv4Addr::from(as_array))
}

pub fn vec_to_ip6(vec : &[u16]) -> Result<Ipv6Addr, String> {
    let as_array = <[u16; 8]>::try_from(&vec[..])
        .map_err(|err| format!("Cannot convert vec to array {:?}", err))?;

    Ok(Ipv6Addr::from(as_array))
}

pub const VSOCK_PARENT_CID: u32 = 3; // From AWS Nitro documentation.

pub const DATA_SOCKET : u32 = 100;

pub const PACKET_LOG_STEP : u32 = 5000;

pub fn log_packet_processing(count : u32, step : u32, source : &str) -> u32 {
    let result = count.overflowing_add(1).0;

    if result % step == 0 {
        log::debug!("Successfully served another {} packets from {}!", step, source);
    }

    result
}

pub fn parse_console_argument<T : NumArg>(args: &ArgMatches, name: &str) -> T {
    parse_optional_console_argument(args, name).expect(format!("{} must be specified", name).as_str())
}

pub fn parse_optional_console_argument<T : NumArg>(args: &ArgMatches, name: &str) -> Option<T> {
    args.value_of(name).map(|e| T::parse_arg(e))
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


#[macro_export]
macro_rules! extract_enum_value {
  ($value:expr, $pattern:pat => $extracted_value:expr) => {
    match $value {
        $pattern => Ok($extracted_value),
        x => Err(format!("Expected {:?} for enum variant, but got {:?}", stringify!($pattern), x)),
    }
  };
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UserProgramExitStatus {
    ExitCode(i32),
    TerminatedBySignal
}

pub fn handle_background_task_exit(result : Result<Result<(), String>, JoinError>, task_name : &str) -> Result<UserProgramExitStatus, String> {
    match result {
        Err(err) => {
            Err(format!("Join error in {}. {:?}", task_name, err))?
        }
        Ok(Err(err)) => {
            Err(err)
        }
        // Background tasks never exit with success
        _ => { unreachable!() }
    }
}