pub mod device;
pub mod netlink;
pub mod socket;

use clap::ArgMatches;
use serde::{Deserialize, Serialize};
use tokio::task::{JoinError};

use std::borrow::Borrow;
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;

// 14 bytes constant size Ethernet header (https://en.wikipedia.org/wiki/Ethernet_frame#Header)
// plus 0 or maximum 2 IEEE 802.1Q tags (https://en.wikipedia.org/wiki/IEEE_802.1Q) of size 4 bytes each.
pub const MAX_ETHERNET_HEADER_SIZE: u32 = 22;

pub fn vec_to_ip4(vec: &[u8]) -> Result<Ipv4Addr, String> {
    let as_array = <[u8; 4]>::try_from(&vec[..]).map_err(|err| format!("Cannot convert vec to array {:?}", err))?;

    Ok(Ipv4Addr::from(as_array))
}

pub fn vec_to_ip6(vec: &[u16]) -> Result<Ipv6Addr, String> {
    let as_array = <[u16; 8]>::try_from(&vec[..]).map_err(|err| format!("Cannot convert vec to array {:?}", err))?;

    Ok(Ipv6Addr::from(as_array))
}

pub const VSOCK_PARENT_CID: u32 = 3; // From AWS Nitro documentation.

pub const PACKET_LOG_STEP: u32 = 5000;

pub fn log_packet_processing(count: u32, step: u32, source: &str) -> u32 {
    let result = count.overflowing_add(1).0;

    if result % step == 0 {
        log::debug!("Successfully served another {} packets from {}!", step, source);
    }

    result
}

pub fn parse_console_argument<T: NumArg>(args: &ArgMatches, name: &str) -> T {
    parse_optional_console_argument(args, name).expect(format!("{} must be specified", name).as_str())
}

pub fn parse_optional_console_argument<T: NumArg>(args: &ArgMatches, name: &str) -> Option<T> {
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

/// Deconstructs enum using provided pattern expression `$pattern` => `$extracted_value`
/// # Returns
/// `Ok($extracted_value)` if `$value` matches `$pattern` and `Err` otherwise
#[macro_export]
macro_rules! extract_enum_value {
    ($value:expr, $pattern:pat => $extracted_value:expr) => {
        match $value {
            $pattern => Ok($extracted_value),
            x => Err(format!(
                "Expected {:?} for enum variant, but got {:?}",
                stringify!($pattern),
                x
            )),
        }
    };
}

/// Finds first value in iterable `$value` that matches provided pattern expression `pattern` => `extracted_value`
/// The type of `$value`must implement `IntoIterator` for this macros to work
/// # Returns
/// `Some($extracted_value)` if `$value` contains an element that matches `$pattern` and `None` otherwise
#[macro_export]
macro_rules! find_map {
    ($value:expr, $pattern:pat => $extracted_value:expr) => {
        $value.iter().find_map(|e| match e {
            $pattern => Some($extracted_value),
            _ => None,
        })
    };
}

/// Executes block of code `$value` asynchronously while simultaneously checking on `tasks` futures
/// If any future from `$tasks` list completes (with error or not) before `$value` the whole block exits with an `Err`
/// # Returns
/// The result of `$value` block when it completes or `Err` if any future from `$tasks` list completes first
#[macro_export]
macro_rules! with_background_tasks {
    ($tasks:expr, $value:block) => {{
        use futures::StreamExt;
        use shared::handle_background_task_exit;

        tokio::select! {
            result = $tasks.next() => {
                handle_background_task_exit(result)
            },
            result = async { $value } => {
                result
            },
        }
    }};
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UserProgramExitStatus {
    ExitCode(i32),
    TerminatedBySignal,
}

pub fn handle_background_task_exit<T>(result: Option<Result<Result<(), String>, JoinError>>) -> Result<T, String> {
    match result {
        Some(Err(err)) => {
            if let Ok(reason) = err.try_into_panic() {
                Err(format!("Background task panicked at {:?}", reason))
            } else {
                Err(format!("Background task has been cancelled."))
            }
        }
        Some(Ok(Err(err))) => Err(format!("Background task finished with error. {}", err)),

        // Background tasks should never exit with success inside `with_background_tasks` block
        _ => Err(format!("Background task finished unexpectedly.")),
    }
}
