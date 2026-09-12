/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::netlink::arp::ARPEntry;
use crate::netlink::route::{Gateway, Route};
use crate::AppLogPortInfo;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
pub enum SetupMessages {
    NoMoreCertificates,
    NetworkDeviceSettings(Vec<NetworkDeviceSettings>),
    PrivateNetworkDeviceSettings(PrivateNetworkDeviceSettings),
    GlobalNetworkSettings(GlobalNetworkSettings),
    CSR(String),
    Certificate(String),
    UserProgramExit(Result<UserProgramExitStatus, String>),
    ApplicationConfig(ApplicationConfiguration),
    NBDConfiguration(NBDConfiguration),
    EnvVariables(Vec<(String, String)>),
    ExtraUserProgramArguments(Vec<String>),
    ExitEnclave,
    EncryptedSpaceAvailable(usize),
    AppLogPort(Vec<AppLogPortInfo>),
    NodeAgentUrl(Option<String>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NBDConfiguration {
    pub address: IpAddr,

    pub exports: Vec<NBDExport>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NBDExport {
    pub name: String,

    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApplicationConfiguration {
    pub id: Option<String>,

    pub skip_server_verify: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkDeviceSettings {
    pub vsock_port_number: u32,

    pub self_l2_address: [u8; 6],

    pub self_l3_address: IpNetwork,

    pub name: String,

    pub mtu: u32,

    pub gateway: Option<Gateway>,

    pub routes: Vec<Route>,

    pub static_arp_entries: Vec<ARPEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PrivateNetworkDeviceSettings {
    pub vsock_port_number: u32,

    pub l3_address: IpNetwork,

    pub name: String,

    pub mtu: u32,
}

pub type HostEntries = HashMap<IpAddr, Vec<String>>;

#[derive(Serialize, Deserialize, Debug)]
pub struct GlobalNetworkSettings {
    pub hostname: String,
    pub host_entries: HostEntries,
    pub resolv_config: ResolvConfig,
}

/// Data structure that represents the content of /etc/resolv.conf file from
/// the parents that we want to pass to the enclave. It is following the description
/// from: https://man7.org/linux/man-pages/man5/resolv.conf.5.html
#[derive(Serialize, Deserialize, Debug)]
pub struct ResolvConfig {
    /// Lists of nameservers, in the order of appearance
    pub nameservers: Vec<String>,
    /// The entry of search domain, only the last one is considered
    pub search: Option<String>,
    /// lists of option entry, if any, and has to be as
    pub options: Vec<ResolvConfigOption>,
    /// list of sort-list IP
    pub sortlist: Vec<String>,
}

impl ResolvConfig {
    pub fn empty() -> Self {
        Self {
            nameservers: vec![],
            search: None,
            options: vec![],
            sortlist: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum ResolvConfigOption {
    Debug,
    NDots(u8),
    Timeout(u8),
    Attempts(u8),
    Rotate,
    NoAAAA,
    NoCheckNames,
    Inet6,
    Ip6ByteString,
    Ip6DotInt,
    NoIp6DotInt,
    EDns0,
    SingleRequest,
    SingleRequestReopen,
    NoTldQuery,
    UseVc,
    NoReload,
    TrustAd,
}

impl Display for ResolvConfigOption {
    #[rustfmt::skip]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        use ResolvConfigOption::*;
        match self {
            Debug               => write!(f, "debug"),
            Rotate              => write!(f, "rotate"),
            NoAAAA              => write!(f, "no-aaaa"),
            NoCheckNames        => write!(f, "no-check-names"),
            Inet6               => write!(f, "inet6"),
            Ip6ByteString       => write!(f, "ip6-bytestring"),
            Ip6DotInt           => write!(f, "ip6-dotint"),
            NoIp6DotInt         => write!(f, "no-ip6-dotint"),
            EDns0               => write!(f, "edns0"),
            SingleRequest       => write!(f, "single-request"),
            SingleRequestReopen => write!(f, "single-request-reopen"),
            NoTldQuery          => write!(f, "no-tld-query"),
            UseVc               => write!(f, "use-vc"),
            TrustAd             => write!(f, "trust-ad"),
            NoReload            => write!(f, "no-reload"),
            NDots(n)            => write!(f, "ndots:{n}"),
            Timeout(n)          => write!(f, "timeout:{n}"),
            Attempts(n)         => write!(f, "attempts:{n}"),
        }
    }
}

impl TryFrom<&str> for ResolvConfigOption {
    type Error = String;

    #[rustfmt::skip]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        use ResolvConfigOption::*;
        Ok(match value {
            "debug"                 => Debug,
            "rotate"                => Rotate,
            "no-aaaa"               => NoAAAA,
            "no-check-names"        => NoCheckNames,
            "inet6"                 => Inet6,
            "ip6-bytestring"        => Ip6ByteString,
            "ip6-dotint"            => Ip6DotInt,
            "no-ip6-dotint"         => NoIp6DotInt,
            "edns0"                 => EDns0,
            "single-request"        => SingleRequest,
            "single-request-reopen" => SingleRequestReopen,
            "no-tld-query"          => NoTldQuery,
            "use-vc"                => UseVc,
            "no-reload"             => NoReload,
            "trust-ad"              => TrustAd,
            x => {
                let mut splitted = x.split(':');
                let first_part = splitted
                    .next()
                    .ok_or(format!("invalid resolv.conf option, missing option token"))?;
                let second_num = splitted
                    .next()
                    .ok_or(format!("invalid resolv.conf option, missing numeric token"))
                    .and_then(|x| {
                        u8::from_str_radix(x, 10).map_err(|_| {
                            format!("invalid resolv.conf option, invalid numeric token: {x}")
                        })
                    })?;

                match first_part {
                    "ndots" => NDots(second_num),
                    "timeout" => Timeout(second_num),
                    "attempts" => Attempts(second_num),
                    _ => return Err(format!("invalid resolv.conf option")),
                }
            }
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileWithPath {
    pub path: String,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum UserProgramExitStatus {
    ExitCode(i32),
    TerminatedBySignal,
}
