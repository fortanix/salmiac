/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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

    pub global_settings_list: Vec<FileWithPath>,
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
/// Should not contain internal error details.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveErrorCode {
    EnclaveFailure,
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
