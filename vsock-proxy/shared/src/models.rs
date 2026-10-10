/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::netlink::arp::ARPEntry;
use crate::netlink::route::{Gateway, Route};
use crate::AppLogPortInfo;
use std::collections::HashMap;

use resolv_conf::Config;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvConfig(Config);

impl Serialize for ResolvConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for ResolvConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        Config::parse(&s)
            .map(ResolvConfig)
            .map_err(serde::de::Error::custom)
    }
}

impl ResolvConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let mut parent_resolv = File::open(&path)
            .map_err(|err| format!("Could not open {:?}. {:?}", path.as_ref(), err))?;

        let mut config_bytes: Vec<u8> = vec![];
        let _ = parent_resolv
            .read_to_end(&mut config_bytes)
            .map_err(|e| format!("unable to read resolv.conf file: {e}"))?;

        let config =
            Config::parse(&config_bytes).map_err(|e| format!("resolv.conf parsing error: {e}"))?;

        Ok(Self(config))
    }

    pub fn transform_nameservers<F>(&mut self, mut mapper: F) -> Result<(), String>
    where
        F: FnMut(IpAddr) -> Result<Option<IpAddr>, String>,
    {
        self.0.nameservers.iter_mut().try_for_each(|entry| {
            let res = mapper(entry.clone().into())?;

            if let Some(new_ip) = res {
                *entry = new_ip.into();
            }

            Ok(())
        })
    }
}

impl ToString for ResolvConfig {
    fn to_string(&self) -> String {
        self.0.to_string()
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

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr};

    use resolv_conf::Config;

    use crate::models::ResolvConfig;

    #[test]
    fn verify_resolv_conf_generation() {
        let mut resolv_conf = Config::new();
        resolv_conf.nameservers.push(resolv_conf::ScopedIp::V4(
            Ipv4Addr::from_str("192.168.0.10").unwrap(),
        ));
        resolv_conf.set_search(vec![".".to_string()]);
        resolv_conf.edns0 = true;
        resolv_conf.trust_ad = true;

        let conf = ResolvConfig(resolv_conf);

        let res = conf.to_string();

        assert_eq!(
            res,
            r"nameserver 192.168.0.10
search .
options edns0
options trust-ad
"
        );
    }
}
