/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::env;
use std::path::Path;

use api_model::enclave::{FileSystemConfig, UserConfig};
use api_model::simulator::SimulatorEnclavesConversionRequestOptions;

use crate::image_builder::enclave::initramfs::BasicInitramfsBuilder;
use crate::image_builder::enclave::qemu::QemuEnclaveImageBuilder;
use crate::image_builder::enclave::EnclaveSettings;
use crate::image_builder::enclave::GenericEnclaveImageBuilder;
use crate::DockerUtil;
use crate::Result;

pub(crate) struct EnclaveImageBuilder<'a> {
    pub(crate) enclave_image_builder: GenericEnclaveImageBuilder<'a>,
}

impl<'a> EnclaveImageBuilder<'a> {
    pub const INITRAMFS_FILENAME: &'static str = "initramfs.gz";

    pub(crate) async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        enclave_settings: EnclaveSettings,
        user_config: UserConfig,
        env_vars: Vec<String>,
        sender: std::sync::mpsc::Sender<crate::image::ImageToClean>,
    ) -> Result<()> {
        QemuEnclaveImageBuilder::create_image(
            self,
            docker_util,
            enclave_settings,
            user_config,
            env_vars,
            sender,
        )
        .await
    }

    pub(crate) fn get_enclave_base_details(
        _enclaves_options: &SimulatorEnclavesConversionRequestOptions,
    ) -> String {
        crate::ENCLAVE_IMAGE_PATH.to_owned()
    }
}

#[async_trait::async_trait]
impl<'a> QemuEnclaveImageBuilder<'a> for EnclaveImageBuilder<'a> {
    type Measurements = ();
    type InitramfsBuilder = BasicInitramfsBuilder;

    fn enclave_image_builder(&self) -> &GenericEnclaveImageBuilder<'a> {
        &self.enclave_image_builder
    }

    #[allow(unused)]
    fn ovmf_filename(&self) -> &'static str {
        ""
    }

    fn initramfs_filename(&self) -> &'static str {
        Self::INITRAMFS_FILENAME
    }

    async fn create_block_file(
        &self,
        docker_util: &dyn DockerUtil,
        user_config: &UserConfig,
        _enclave_settings: &EnclaveSettings,
    ) -> Result<FileSystemConfig> {
        let file_system_config = self
            .enclave_image_builder
            .create_block_file(docker_util, &user_config)
            .await?;
        Ok(file_system_config)
    }

    async fn compute_launch_measurements(
        &self,
        _enclave_settings: &EnclaveSettings,
        _initramfs_file_path: &Path,
    ) -> Result<Self::Measurements> {
        Ok(())
    }
}
