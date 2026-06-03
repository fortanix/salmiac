/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::env;
use std::path::Path;
use std::sync::mpsc::Sender;

use api_model::enclave::{EnclaveManifest, UserConfig};
use api_model::nitro::NitroEnclavesConversionRequestOptions;
use docker_image_reference::Reference as DockerReference;
use log::info;
use serde::Deserialize;

use crate::docker::DockerUtil;
use crate::file::BuildContext;
use crate::image::{ImageKind, ImageToClean};
use crate::image_builder::enclave::EnclaveSettings;
use crate::{run_subprocess, ConverterError, ConverterErrorKind, Result};

#[derive(Deserialize)]
pub(crate) struct NitroEnclaveMeasurements {
    #[serde(rename(deserialize = "Measurements"))]
    pub(crate) pcr_list: PCRList,
}

#[derive(Deserialize)]
pub(crate) struct PCRList {
    #[serde(alias = "PCR0")]
    pub(crate) pcr0: String,
    #[serde(alias = "PCR1")]
    pub(crate) pcr1: String,
    #[serde(alias = "PCR2")]
    pub(crate) pcr2: String,
    /// Only present if enclave file is built with signing certificate
    #[serde(alias = "PCR8")]
    pub(crate) pcr8: Option<String>,
}

async fn create_nitro_image(
    image: &DockerReference<'_>,
    output_file: &Path,
) -> Result<NitroEnclaveMeasurements> {
    let output = output_file.to_str().ok_or(ConverterError {
        message: format!("Failed to cast path {:?} to string", output_file),
        kind: ConverterErrorKind::NitroFileCreation,
    })?;

    let image_as_str = image.to_string();

    let nitro_cli_args = [
        "build-enclave",
        "--docker-uri",
        &image_as_str,
        "--output-file",
        output,
    ];

    let process_output = run_subprocess("nitro-cli", &nitro_cli_args)
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::NitroFileCreation,
        })?;

    serde_json::from_str::<NitroEnclaveMeasurements>(&process_output).map_err(|err| {
        ConverterError {
            message: format!("Bad measurements. {:?}", err),
            kind: ConverterErrorKind::NitroFileCreation,
        }
    })
}

pub(crate) struct EnclaveImageBuilder<'a> {
    pub(crate) enclave_image_builder: crate::image_builder::enclave::EnclaveImageBuilder<'a>,
}

impl<'a> EnclaveImageBuilder<'a> {
    pub const ENCLAVE_FILE_NAME: &'static str = "enclave.eif";

    pub(crate) async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        enclave_settings: EnclaveSettings,
        user_config: UserConfig,
        env_vars: Vec<String>,
        images_to_clean_snd: Sender<ImageToClean>,
    ) -> Result<NitroEnclaveMeasurements> {
        let is_debug = enclave_settings.is_debug;
        let enable_overlay_filesystem_persistence =
            enclave_settings.enable_overlay_filesystem_persistence;
        let ccm_backend_url = enclave_settings.ccm_backend_url.clone();
        let dsm_configuration = enclave_settings.dsm_configuration.clone();

        let build_context =
            BuildContext::new(&self.enclave_image_builder.dir.path()).map_err(|message| {
                ConverterError {
                    message,
                    kind: ConverterErrorKind::RequisitesCreation,
                }
            })?;

        self.enclave_image_builder
            .create_requisites(enclave_settings, &build_context)
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        let file_system_config = self
            .enclave_image_builder
            .create_block_file(docker_util, &user_config)
            .await?;
        info!("Client FS Block file has been created.");

        let enclave_manifest = EnclaveManifest {
            user_config,
            file_system_config,
            is_debug,
            env_vars,
            enable_overlay_filesystem_persistence,
            ccm_backend_url,
            dsm_configuration,
        };

        crate::image_builder::enclave::EnclaveImageBuilder::create_manifest_file(
            enclave_manifest,
            &build_context,
        )?;

        info!("Enclave build prerequisites have been created!");

        let build_context_archive_file = build_context
            .package_into_archive(
                &self
                    .enclave_image_builder
                    .dir
                    .path()
                    .join("enclave-build-context.tar"),
            )
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        // This image is made temporary because it is only used by nitro-cli to create an `.eif` file.
        // After nitro-cli finishes we can safely reclaim it.
        let result_image_raw = self.enclave_image_builder.enclave_image();

        let result_reference =
            DockerReference::from_str(&result_image_raw).map_err(|message| ConverterError {
                message: format!("Failed to create enclave image reference. {:?}", message),
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        let result = docker_util
            .create_image_from_archive(result_reference, build_context_archive_file)
            .await
            .map(|e| e.make_temporary(ImageKind::Intermediate, images_to_clean_snd))
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::EnclaveImageCreation,
            })?;

        let nitro_measurements = {
            let nitro_image_path = &self
                .enclave_image_builder
                .dir
                .path()
                .join(EnclaveImageBuilder::ENCLAVE_FILE_NAME);

            create_nitro_image(&result.image.reference, &nitro_image_path).await?
        };

        info!("Nitro image has been created!");

        Ok(nitro_measurements)
    }

    pub(crate) fn get_enclave_base_details(
        _enclaves_options: &NitroEnclavesConversionRequestOptions,
    ) -> (String, String) {
        (
            env::var("ENCLAVE_IMAGE").unwrap_or(crate::ENCLAVE_IMAGE.to_owned()),
            crate::ENCLAVE_IMAGE_PATH.to_owned(),
        )
    }
}
