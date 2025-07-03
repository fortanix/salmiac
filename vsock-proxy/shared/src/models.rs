/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::net::IpAddr;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use crate::AppLogPortInfo;

use crate::netlink::arp::ARPEntry;
use crate::netlink::route::{Gateway, Route};

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

#[derive(Serialize, Deserialize, Debug)]
pub struct GlobalNetworkSettings {
    pub hostname: String,

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
