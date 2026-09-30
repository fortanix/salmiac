/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::netlink::arp::ARPEntry;
use crate::netlink::route::{Gateway, Route};
use crate::AppLogPortInfo;
use std::collections::HashMap;

use resolv_conf::{Config, Family, Lookup, Network, ScopedIp};

#[derive(Serialize, Deserialize, Debug)]
pub enum SetupMessages {
    NoMoreCertificates,
    NetworkDeviceSettings(Vec<NetworkDeviceSettings>),
    PrivateNetworkDeviceSettings(PrivateNetworkDeviceSettings),
    GlobalNetworkSettings(GlobalNetworkSettings),
    CSR(String),
    Certificate(String),
    UserProgramExit(Result<UserProgramExitStatus, EnclaveErrorCode>),
    ApplicationConfig(ApplicationConfiguration),
    NBDConfiguration(NBDConfiguration),
    EnvVariables(Vec<(String, String)>),
    ExtraUserProgramArguments(Vec<String>),
    ExitEnclave,
    EncryptedSpaceAvailable(usize),
    AppLogPort(Vec<AppLogPortInfo>),
    NodeAgentUrl(Option<String>),
    CertificateError(CertificateErrorCode),
}

impl SetupMessages {
    /// Returns the variant name without exposing any message payload.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::NoMoreCertificates => "NoMoreCertificates",
            Self::NetworkDeviceSettings(_) => "NetworkDeviceSettings",
            Self::PrivateNetworkDeviceSettings(_) => "PrivateNetworkDeviceSettings",
            Self::GlobalNetworkSettings(_) => "GlobalNetworkSettings",
            Self::CSR(_) => "CSR",
            Self::Certificate(_) => "Certificate",
            Self::UserProgramExit(_) => "UserProgramExit",
            Self::ApplicationConfig(_) => "ApplicationConfig",
            Self::NBDConfiguration(_) => "NBDConfiguration",
            Self::EnvVariables(_) => "EnvVariables",
            Self::ExtraUserProgramArguments(_) => "ExtraUserProgramArguments",
            Self::ExitEnclave => "ExitEnclave",
            Self::EncryptedSpaceAvailable(_) => "EncryptedSpaceAvailable",
            Self::AppLogPort(_) => "AppLogPort",
            Self::NodeAgentUrl(_) => "NodeAgentUrl",
            Self::CertificateError(_) => "CertificateError",
        }
    }
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
    pub nameservers: Vec<String>,
    pub last_search: String,
    pub domain: Option<String>,
    pub search: Option<Vec<String>>,
    pub sortlist: Vec<String>,
    pub debug: bool,
    pub ndots: u32,
    pub timeout: u32,
    pub attempts: u32,
    pub rotate: bool,
    pub no_check_names: bool,
    pub inet6: bool,
    pub ip6_bytestring: bool,
    pub ip6_dotint: bool,
    pub edns0: bool,
    pub single_request: bool,
    pub single_request_reopen: bool,
    pub no_tld_query: bool,
    pub use_vc: bool,
    pub no_reload: bool,
    pub trust_ad: bool,
    pub lookup: Vec<String>,
    pub family: Vec<String>,
    pub no_aaaa: bool,
}

impl ResolvConfig {
    pub fn empty() -> Self {
        Self {
            nameservers: vec![],
            last_search: "".to_string(),
            domain: None,
            search: None,
            sortlist: vec![],
            debug: false,
            ndots: 1,
            timeout: 5,
            attempts: 2,
            rotate: false,
            no_check_names: false,
            inet6: false,
            ip6_bytestring: false,
            ip6_dotint: false,
            edns0: false,
            single_request: false,
            single_request_reopen: false,
            no_tld_query: false,
            use_vc: false,
            no_reload: false,
            trust_ad: false,
            lookup: vec![],
            family: vec![],
            no_aaaa: false,
        }
    }
}

impl ResolvConfig {
    pub fn from_lookup(lookup: &Lookup) -> String {
        match lookup {
            Lookup::File => "file",
            Lookup::Bind => "bind",
            Lookup::Extra(s) => s.as_str(),
        }
        .to_string()
    }

    pub fn to_lookup(value: &str) -> Lookup {
        match value.to_lowercase().as_str() {
            "file" => Lookup::File,
            "bind" => Lookup::Bind,
            s => Lookup::Extra(s.to_string()),
        }
    }

    pub fn from_family(family: &Family) -> String {
        match family {
            Family::Inet4 => "inet4",
            Family::Inet6 => "inet6",
        }
        .to_string()
    }

    pub fn to_family(value: &str) -> Result<Family, String> {
        match value.to_lowercase().as_str() {
            "inet4" => Ok(Family::Inet4),
            "inet6" => Ok(Family::Inet6),
            s => Err(format!(
                "invalid family enumeration '{s}', expected 'inet4' or 'inet6'"
            )),
        }
    }

    fn check_last_search(value: &Config) -> String {
        let domain_list: Vec<&String> = value.get_last_search_or_domain().collect();

        let ret = if domain_list.len() == 0 {
            "none" // If nothing, it is "none"
        } else if domain_list.len() > 1 {
            "search" // If it is more than one, it is definitely "search"
        } else {
            if let Some(domain) = value.get_domain() {
                if domain.eq(domain_list[0]) {
                    "domain"
                } else {
                    "search"
                }
            } else {
                "search"
            }
        };

        ret.to_string()
    }

    pub fn parse_resolv_conf<P: AsRef<Path>>(path: P) -> Result<ResolvConfig, String> {
        let mut parent_resolv = File::open(&path)
            .map_err(|err| format!("Could not open {:?}. {:?}", path.as_ref(), err))?;

        let mut config_bytes: Vec<u8> = vec![];
        let _ = parent_resolv
            .read_to_end(&mut config_bytes)
            .map_err(|e| format!("unable to read resolv.conf file: {e}"))?;

        let config =
            Config::parse(&config_bytes).map_err(|e| format!("resolv.conf parsing error: {e}"))?;

        config.try_into()
    }

    pub fn write_resolv_conf(&self) -> Result<String, String> {
        let config: Config = self.try_into()?;
        Ok(config.to_string())
    }
}

impl TryFrom<Config> for ResolvConfig {
    type Error = String;

    fn try_from(value: Config) -> Result<Self, Self::Error> {
        Ok(Self {
            nameservers: value.nameservers.iter().map(|f| f.to_string()).collect(),
            last_search: ResolvConfig::check_last_search(&value),
            domain: value.get_domain().cloned(),
            search: value.get_search().cloned(),
            sortlist: value.sortlist.iter().map(|f| f.to_string()).collect(),
            debug: value.debug,
            ndots: value.ndots,
            timeout: value.timeout,
            attempts: value.attempts,
            rotate: value.rotate,
            no_check_names: value.no_check_names,
            inet6: value.inet6,
            ip6_bytestring: value.ip6_bytestring,
            ip6_dotint: value.ip6_dotint,
            edns0: value.edns0,
            single_request: value.single_request,
            single_request_reopen: value.single_request_reopen,
            no_tld_query: value.no_tld_query,
            use_vc: value.use_vc,
            no_reload: value.no_reload,
            trust_ad: value.trust_ad,
            lookup: value
                .lookup
                .iter()
                .map(|f| ResolvConfig::from_lookup(f))
                .collect(),
            family: value
                .family
                .iter()
                .map(|f| ResolvConfig::from_family(f))
                .collect(),
            no_aaaa: value.no_aaaa,
        })
    }
}

impl TryInto<Config> for &ResolvConfig {
    type Error = String;

    fn try_into(self) -> Result<Config, Self::Error> {
        let mut config = Config::new();
        config.nameservers = self
            .nameservers
            .iter()
            .map(|f| ScopedIp::from_str(f))
            .collect::<Result<Vec<ScopedIp>, _>>()
            .map_err(|e| e.to_string())?;

        match self.last_search.as_str() {
            "none" => Ok(()),
            "search" => {
                if let Some(domain) = &self.domain {
                    config.set_domain(domain.clone());
                }
                if let Some(search) = &self.search {
                    config.set_search(search.clone());
                }
                Ok(())
            }
            "domain" => {
                if let Some(search) = &self.search {
                    config.set_search(search.clone());
                }
                if let Some(domain) = &self.domain {
                    config.set_domain(domain.clone());
                }
                Ok(())
            }
            x => Err(format!(
                "invalid last_search value '{x}', allowed: none, search, domain"
            )),
        }?;

        config.sortlist = self
            .sortlist
            .iter()
            .map(|f| Network::from_str(&f))
            .collect::<Result<Vec<Network>, _>>()
            .map_err(|e| e.to_string())?;

        config.debug = self.debug;
        config.ndots = self.ndots;
        config.timeout = self.timeout;
        config.attempts = self.attempts;
        config.rotate = self.rotate;
        config.no_check_names = self.no_check_names;
        config.inet6 = self.inet6;
        config.ip6_bytestring = self.ip6_bytestring;
        config.ip6_dotint = self.ip6_dotint;
        config.edns0 = self.edns0;
        config.single_request = self.single_request;
        config.single_request_reopen = self.single_request_reopen;
        config.no_tld_query = self.no_tld_query;
        config.use_vc = self.use_vc;
        config.no_reload = self.no_reload;
        config.trust_ad = self.trust_ad;

        config.lookup = self
            .lookup
            .iter()
            .map(|f| ResolvConfig::to_lookup(f.as_str()))
            .collect();

        config.family = self
            .family
            .iter()
            .map(|f| ResolvConfig::to_family(f.as_str()))
            .collect::<Result<Vec<Family>, _>>()?;

        config.no_aaaa = self.no_aaaa;

        Ok(config)
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

/// Public failure codes crossing the enclave boundary.
/// Internal error details are included only when conversion debug mode is enabled.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum EnclaveErrorCode {
    EnclaveFailure(Option<String>),
}

impl EnclaveErrorCode {
    /// Discard internal details unless the enclave manifest enables debug mode.
    pub fn enclave_failure(message: String, is_debug: bool) -> Self {
        Self::EnclaveFailure(if is_debug { Some(message) } else { None })
    }
}

/// Certificate failures without payload to prevent
/// sensitive information leaking
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateErrorCode {
    Unavailable,
    Timeout,
    RequestFailed,
    InternalError,
}
