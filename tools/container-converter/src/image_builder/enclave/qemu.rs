/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use log::info;
use std::path::Path;
use std::time::Instant;

use api_model::enclave::{EnclaveManifest, FileSystemConfig, UserConfig};
use async_trait::async_trait;

use crate::image_builder::enclave::initramfs::InitramfsBuilder;
use crate::image_builder::enclave::EnclaveSettings;
use crate::image_builder::enclave::GenericEnclaveImageBuilder;
use crate::DockerUtil;
use crate::{ConverterError, ConverterErrorKind, Result};

pub(crate) const DEFAULT_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[async_trait]
pub(crate) trait QemuEnclaveImageBuilder<'a> {
    type Measurements;
    type InitramfsBuilder: InitramfsBuilder;

    fn enclave_image_builder(&self) -> &GenericEnclaveImageBuilder<'a>;
    #[cfg_attr(platform = "simulator", allow(unused))]
    fn ovmf_filename(&self) -> &'static str;
    fn initramfs_filename(&self) -> &'static str;
    async fn create_block_file(
        &self,
        docker_util: &dyn DockerUtil,
        user_config: &UserConfig,
        enclave_settings: &EnclaveSettings,
    ) -> Result<FileSystemConfig>;

    // Function to update/override env variables passed to enclave manifest file
    fn update_env_vars(&self, _enclave_settings: &EnclaveSettings, _env_vars: &mut Vec<String>) {}

    async fn compute_launch_measurements(
        &self,
        enclave_settings: &EnclaveSettings,
        initramfs_file_path: &Path,
    ) -> Result<Self::Measurements>;

    async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        enclave_settings: EnclaveSettings,
        user_config: UserConfig,
        mut env_vars: Vec<String>,
        _sender: std::sync::mpsc::Sender<crate::image::ImageToClean>,
    ) -> Result<Self::Measurements> {
        let work_dir = self.enclave_image_builder().dir.path();

        let start = Instant::now();
        info!("Creating client FS block file...");
        let file_system_config = self
            .create_block_file(docker_util, &user_config, &enclave_settings)
            .await?;
        info!(
            "Client FS block file has been created in {:?}.",
            start.elapsed()
        );

        let start = Instant::now();
        let is_debug = enclave_settings.is_debug;
        let enable_overlay_filesystem_persistence =
            enclave_settings.enable_overlay_filesystem_persistence;
        let ccm_backend_url = enclave_settings.ccm_backend_url.clone();
        let dsm_configuration = enclave_settings.dsm_configuration.clone();

        self.update_env_vars(&enclave_settings, &mut env_vars);

        let enclave_manifest = EnclaveManifest {
            user_config,
            file_system_config,
            is_debug,
            env_vars,
            enable_overlay_filesystem_persistence,
            ccm_backend_url,
            dsm_configuration,
        };

        let enclave_manifest_data =
            serde_json::to_vec(&enclave_manifest).map_err(|err| ConverterError {
                message: format!("Failed serializing enclave settings file. {:?}", err),
                kind: ConverterErrorKind::RequisitesCreation,
            })?;
        info!("Serialized enclave manifest in {:?}.", start.elapsed());

        let enclave_base_tar_path = work_dir.join(crate::ENCLAVE_IMAGE_PATH);
        let start = Instant::now();
        info!("Exporting enclave-base image...");
        let enclave_base_archive = self
            .enclave_image_builder()
            .export_enclave_base_file_system(docker_util, &enclave_base_tar_path)
            .await?;
        info!("Exported enclave-base image in {:?}.", start.elapsed());

        let initramfs_file_path = work_dir.join(self.initramfs_filename());

        info!("Creating initramfs archive...");
        Self::InitramfsBuilder::build(
            &initramfs_file_path,
            &enclave_settings,
            enclave_base_archive,
            &enclave_manifest_data,
        )
        .map_err(|e| ConverterError {
            message: format!("Failed to create initramfs: {}", e),
            kind: ConverterErrorKind::EnclaveImageCreation,
        })?;

        self.compute_launch_measurements(&enclave_settings, &initramfs_file_path)
            .await
    }
}
