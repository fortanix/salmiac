/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod models;
pub mod netlink;
pub mod socket;
pub mod tap;

use std::borrow::Borrow;
use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::ParseIntError;

use async_process::{Command, Stdio};
use clap::ArgMatches;
use futures::stream::FuturesUnordered;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

// 14 bytes constant size Ethernet header (https://en.wikipedia.org/wiki/Ethernet_frame#Header)
// plus 0 or maximum 2 IEEE 802.1Q tags (https://en.wikipedia.org/wiki/IEEE_802.1Q) of size 4 bytes each.
const MAX_ETHERNET_HEADER_SIZE: u32 = 22;

// Domain Name Service resolver file, contains configuration required to perform a DNS translation (Domain name into an IP address).
// https://man7.org/linux/man-pages/man5/resolv.conf.5.html
pub const DNS_RESOLV_FILE: &'static str = "/etc/resolv.conf";

// Hosts file, contains a simple static association between an IP address and a host name.
// This file doesn't describe any DNS servers compared to "/etc/resolv.conf" and is usually used
// to resolve internal (to the network) resources.
// https://man7.org/linux/man-pages/man5/hosts.5.html
pub const HOSTS_FILE: &'static str = "/etc/hosts";

// Local host name file, configures the name of the local system.
// The file should contain a single newline-terminated hostname string.
// https://man7.org/linux/man-pages/man5/hostname.5.html
pub const HOSTNAME_FILE: &'static str = "/etc/hostname";

// The Name Service Switch file, contains configuration to determine the sources from which to obtain
// name-service information in a range of categories and in what order.
// https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html
pub const NS_SWITCH_FILE: &'static str = "/etc/nsswitch.conf";

// The types of std streams which are forwarded from the client
// application to the parent for better logging
#[derive(Serialize, Deserialize, Debug, PartialEq, Copy, Clone)]
pub enum StreamType {
    Stdout,
    Stderr,
}

// The data shared between the parent and enclave to
// forward client application logs
#[derive(Serialize, Deserialize, Debug)]
pub struct AppLogPortInfo {
    pub sock_addr: SocketAddr,
    pub stream_type: StreamType,
}

/// Converts array slice into a `Ipv4Addr`
/// # Returns
/// `Ok` if slice has a size of 4 elements and `Err` otherwise
pub fn vec_to_ip4(vec: &[u8]) -> Result<Ipv4Addr, String> {
    let as_array = <[u8; 4]>::try_from(&vec[..]).map_err(|err| format!("Cannot convert vec to array {:?}", err))?;

    Ok(Ipv4Addr::from(as_array))
}

/// Converts array slice into a `Ipv6Addr`
/// # Returns
/// `Ok` if slice has a size of 8 elements and `Err` otherwise
pub fn vec_to_ip6(vec: &[u16]) -> Result<Ipv6Addr, String> {
    let as_array = <[u16; 8]>::try_from(&vec[..]).map_err(|err| format!("Cannot convert vec to array {:?}", err))?;

    Ok(Ipv6Addr::from(as_array))
}

// Context identifier of the parent (https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html)
pub const VSOCK_PARENT_CID: u32 = 3;

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

// Check if a path is an absolute path. If yes, remove the forward slash
// and return a relative path. If no, return the input path as is.
pub fn get_relative_path(s: &std::path::Path) -> &std::path::Path {
    if s.is_absolute() {
        return s.strip_prefix("/").unwrap();
    }
    s
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

/// Finds first value in iterable `$value` that matches provided pattern
/// expression `pattern` => `extracted_value` The type of `$value`must implement
/// `IntoIterator` for this macros to work
/// # Returns
/// `Some($extracted_value)` if `$value` contains an element that matches
/// `$pattern` and `None` otherwise
#[macro_export]
macro_rules! find_map {
    ($value:expr, $pattern:pat => $extracted_value:expr) => {
        $value.iter().find_map(|e| match e {
            $pattern => Some($extracted_value),
            _ => None,
        })
    };
}

/// Executes block of code `$value` asynchronously while simultaneously checking
/// on `tasks` futures. If any future from `$tasks` list completes (with error or
/// not) before `$value` the whole block exits with an `Err`
/// # Returns
/// The result of `$value` block when it completes or `Err` if any future from
/// `$tasks` list completes first
#[macro_export]
macro_rules! with_background_tasks {
    ($tasks:expr, $value:block) => {{
        use futures::StreamExt;
        use tokio::task::JoinError;

        fn handle_background_task_exit<T>(result: Option<Result<Result<(), String>, JoinError>>) -> Result<T, String> {
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

#[derive(Default)]
pub struct CommandOutputConfig {
    pub stdout: Option<Stdio>,

    pub stderr: Option<Stdio>,
}

impl CommandOutputConfig {
    pub fn all_piped() -> Self {
        CommandOutputConfig {
            stdout: Some(Stdio::piped()),
            stderr: Some(Stdio::piped()),
        }
    }

    pub fn all_null() -> Self {
        CommandOutputConfig {
            stdout: Some(Stdio::null()),
            stderr: Some(Stdio::null()),
        }
    }
}

pub async fn run_subprocess(subprocess_path: &str, args: &[&str]) -> Result<(), String> {
    run_subprocess_with_output_setup(subprocess_path, args, CommandOutputConfig::default())
        .await
        .map(|_| ())
}

pub async fn run_subprocess_with_output_setup(
    subprocess_path: &str,
    args: &[&str],
    output_config: CommandOutputConfig,
) -> Result<async_process::Output, String> {
    let mut command = Command::new(subprocess_path);

    command.args(args);

    if let Some(stdout) = output_config.stdout {
        command.stdout(stdout);
    }

    if let Some(stderr) = output_config.stderr {
        command.stderr(stderr);
    }

    debug!("Running subprocess {} {:?}.", subprocess_path, args);
    let process = command
        .spawn()
        .map_err(|err| format!("Failed to run subprocess {}. {:?}. Args {:?}", subprocess_path, err, args))?;

    let output = process.output().await.map_err(|err| {
        format!(
            "Error while waiting for subprocess {} to finish: {:?}. Args {:?}",
            subprocess_path, err, args
        )
    })?;

    if output.status.success() {
        Ok(output)
    } else {
        Err(format!("Process exited with a negative return code. Output is: {:?}", output))
    }
}

pub fn cleanup_tokio_tasks(background_tasks: FuturesUnordered<JoinHandle<Result<(), String>>>) -> Result<(), String> {
    for background_task in &background_tasks {
        while !background_task.is_finished() {
            background_task.abort();
        }
    }

    info!("All background tasks have exited successfully.");
    Ok(())
}
