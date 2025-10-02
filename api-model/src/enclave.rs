/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ops::Deref;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::converter::{CertificateConfig, DsmConfiguration};

/// Required information needed to start an enclave
/// Created by the container-converter and consumed by
/// `vsock-proxy.enclave` program on startup
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EnclaveManifest {
    pub user_config: UserConfig,

    pub file_system_config: FileSystemConfig,

    pub is_debug: bool,

    pub env_vars: Vec<String>,

    pub enable_overlay_filesystem_persistence: bool,

    pub ccm_backend_url: CcmBackendUrl,

    pub dsm_configuration: DsmConfiguration,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FileSystemConfig {
    pub root_hash: String,

    pub hash_offset: u64,
}

impl FileSystemConfig {
    pub fn new(dm_verity_stdout: &str, hash_offset: u64) -> Result<Self, String> {
        let field_header = "Root hash:";
        let root_hash = dm_verity_stdout
            .lines()
            .find(|e| e.starts_with(field_header))
            .map(|e| e.replace(field_header, "").trim().to_string())
            .ok_or(format!(
                "Failed to find {} in stdout. Stdout: {}",
                field_header, dm_verity_stdout
            ))?;

        Ok(Self { root_hash, hash_offset })
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UserConfig {
    pub user_program_config: UserProgramConfig,

    pub certificate_config: Vec<CertificateConfig>,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UserProgramConfig {
    pub entry_point: String,

    pub arguments: Vec<String>,

    pub working_dir: WorkingDir,

    pub user: User,

    pub group: User,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WorkingDir(String);

impl Deref for WorkingDir {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&str> for WorkingDir {
    fn from(value: &str) -> Self {
        if value.is_empty() {
            WorkingDir("/".to_string())
        } else {
            WorkingDir(value.to_string())
        }
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct User(String);

impl Deref for User {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&str> for User {
    fn from(value: &str) -> Self {
        if value.is_empty() {
            User("".to_string())
        } else {
            User(value.to_string())
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CcmBackendUrl {
    pub host: String,

    pub port: u16,
}

impl CcmBackendUrl {
    pub fn new(url: &str) -> Result<Self, String> {
        let split: Vec<_> = url.split(":").collect();

        if split.len() != 2 {
            return Err("ccm_url should be in format <ip address>:<port>".to_string());
        }

        match split[1].parse::<u16>() {
            Err(err) => Err(format!("ccm_url port should be a number. {:?}", err)),
            Ok(port) => Ok(CcmBackendUrl {
                host: split[0].to_string(),
                port,
            }),
        }
    }
}

impl Default for CcmBackendUrl {
    fn default() -> Self {
        CcmBackendUrl {
            host: "ccm.fortanix.com".to_string(),
            port: 443,
        }
    }
}
