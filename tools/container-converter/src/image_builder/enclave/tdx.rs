/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::env;
use std::path::Path;

use api_model::enclave::{FileSystemConfig, UserConfig};
use api_model::tdx::TdxEnclavesMeasurements;
use api_model::EnclavesOptions;

use crate::image_builder::blob_finder::BlobFinder;
use crate::image_builder::enclave::initramfs::GpuSupportedInitramfsBuilder;
use crate::image_builder::enclave::nvidia::insert_nvidia_env_vars;
use crate::image_builder::enclave::qemu::QemuEnclaveImageBuilder;
use crate::image_builder::enclave::tdx_measurement::{
    compute_tdx_launch_measurement, TdxMeasurementInputs,
};
use crate::image_builder::enclave::EnclaveSettings;
use crate::image_builder::enclave::GenericEnclaveImageBuilder;
use crate::Result;
use crate::{ConverterError, DockerUtil};

pub(crate) struct EnclaveImageBuilder<'a> {
    pub(crate) enclave_image_builder: GenericEnclaveImageBuilder<'a>,
}

impl<'a> EnclaveImageBuilder<'a> {
    pub const INITRAMFS_FILENAME: &'static str = "initramfs.gz";
    pub const OVMF_FILENAME: &'static str = "OVMF.inteltdx.fd";

    pub(crate) async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        enclave_settings: EnclaveSettings,
        user_config: UserConfig,
        env_vars: Vec<String>,
        sender: std::sync::mpsc::Sender<crate::image::ImageToClean>,
    ) -> Result<TdxEnclavesMeasurements> {
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

    pub(crate) fn get_enclave_base_details(enclaves_options: &EnclavesOptions) -> (String, String) {
        let image_name = env::var("ENCLAVE_IMAGE").unwrap_or_else(|_| {
            if enclaves_options.enable_gpu_passthrough.unwrap_or_default() {
                crate::ENCLAVE_IMAGE_TDX_GPU.to_owned()
            } else {
                crate::ENCLAVE_IMAGE.to_owned()
            }
        });

        let image_path = if enclaves_options.enable_gpu_passthrough.unwrap_or_default() {
            crate::ENCLAVE_GPU_IMAGE_PATH.to_owned()
        } else {
            crate::ENCLAVE_IMAGE_PATH.to_owned()
        };

        (image_name, image_path)
    }
}

#[async_trait::async_trait]
impl<'a> QemuEnclaveImageBuilder<'a> for EnclaveImageBuilder<'a> {
    type Measurements = TdxEnclavesMeasurements;
    type InitramfsBuilder = GpuSupportedInitramfsBuilder;

    fn enclave_image_builder(&self) -> &GenericEnclaveImageBuilder<'a> {
        &self.enclave_image_builder
    }

    fn ovmf_filename(&self) -> &'static str {
        Self::OVMF_FILENAME
    }

    fn initramfs_filename(&self) -> &'static str {
        Self::INITRAMFS_FILENAME
    }

    async fn create_block_file(
        &self,
        docker_util: &dyn DockerUtil,
        user_config: &UserConfig,
        enclave_settings: &EnclaveSettings,
    ) -> Result<FileSystemConfig> {
        let file_system_config = if enclave_settings.gpu_passthrough {
            self.enclave_image_builder
                .create_block_file_with_nvidia_driver_payload(
                    docker_util,
                    &user_config,
                    &enclave_settings.nvidia_driver_capabilities,
                )
                .await?
        } else {
            self.enclave_image_builder
                .create_block_file(docker_util, &user_config)
                .await?
        };
        Ok(file_system_config)
    }

    fn update_env_vars(&self, enclave_settings: &EnclaveSettings, env_vars: &mut Vec<String>) {
        if enclave_settings.gpu_passthrough {
            insert_nvidia_env_vars(env_vars, &enclave_settings.nvidia_driver_capabilities)
        }
    }

    async fn compute_launch_measurements(
        &self,
        enclave_settings: &EnclaveSettings,
        initramfs_file_path: &Path,
    ) -> Result<Self::Measurements> {
        let ovmf_path = BlobFinder::ovmf_path(self.ovmf_filename());
        let kernel_path = BlobFinder::kernel_path(enclave_settings.gpu_passthrough);
        static CMDLINE: &str = "earlyprintk=serial console=ttyS0 rdinit=/init loglevel=7";

        compute_tdx_launch_measurement(&TdxMeasurementInputs {
            ovmf: &ovmf_path,
            kernel: &kernel_path,
            initrd: initramfs_file_path,
            cmdline: Some(CMDLINE),
            vcpus: enclave_settings.cpu_count,
            memory: enclave_settings.mem_size.clone().ok_or(ConverterError {
                message: "Tdx Image conversion requires mem_size in the \"tdx_enclaves_options\""
                    .to_string(),
                kind: crate::ConverterErrorKind::EnclaveImageCreation,
            })?,
        })
        .await
    }
}
