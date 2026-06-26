/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::env;
use std::path::Path;

use api_model::enclave::UserConfig;
use api_model::tdx::{TDXEnclavesConversionRequestOptions, TDXEnclavesMeasurements};
use api_model::HexString;

use crate::image_builder::enclave::qemu::QemuEnclaveImageBuilder;
use crate::image_builder::enclave::EnclaveSettings;
use crate::image_builder::enclave::GenericEnclaveImageBuilder;
use crate::image_builder::INSTALLATION_DIR;
use crate::DockerUtil;
use crate::Result;

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
    ) -> Result<TDXEnclavesMeasurements> {
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
        enclaves_options: &TDXEnclavesConversionRequestOptions,
    ) -> (String, String) {
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
    type Measurements = TDXEnclavesMeasurements;
    const gpu_passthrough_supported: bool = true;

    fn enclave_image_builder(&self) -> &GenericEnclaveImageBuilder<'a> {
        &self.enclave_image_builder
    }

    fn ovmf_filename(&self) -> &'static str {
        Self::OVMF_FILENAME
    }

    async fn compute_launch_measurements(
        &self,
        _enclave_settings: &EnclaveSettings,
        _initramfs_file_path: &Path,
    ) -> Result<Self::Measurements> {
        // TODO (RTE-998): Implement actual measurements call.
        Ok(TDXEnclavesMeasurements {
            mrtd: HexString::new([0]),
            rtmr0: HexString::new([0]),
            rtmr1: HexString::new([0]),
            rtmr2: HexString::new([0]),
            rtmr3: HexString::new([0]),
        })
    }
}
