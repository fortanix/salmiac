/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::fs;
use std::io::{Cursor, Error, ErrorKind};
use std::path::Path;

use api_model::enclave::{EnclaveManifest, UserConfig};
use api_model::snp::SNPEnclavesMeasurements;
use api_model::HexString;
use fortanix_vme_initramfs::{FsTree, Initramfs};
use log::info;

use crate::file::Resource;
use crate::image_builder::enclave::EnclaveImageBuilder as GenericEnclaveImageBuilder;
use crate::image_builder::enclave::EnclaveSettings;
use crate::image_builder::INSTALLATION_DIR;
use crate::{ConverterError, ConverterErrorKind, Result};

pub(crate) struct EnclaveImageBuilder<'a> {
    pub(crate) enclave_image_builder: GenericEnclaveImageBuilder<'a>,
}

impl<'a> EnclaveImageBuilder<'a> {
    const INIT_BIN: Resource<'static> = Resource {
        name: "init",
        data: include_bytes!("../../resources/enclave/init"),
        is_executable: true,
    };
    const GPU_MODULES: &'static [Resource<'static>] = &[
        Resource {
            name: "nvidia.ko",
            data: include_bytes!("../../resources/enclave/kernel_enabled_gpu/nvidia.ko"),
            is_executable: false,
        },
        Resource {
            name: "nvidia-uvm.ko",
            data: include_bytes!("../../resources/enclave/kernel_enabled_gpu/nvidia-uvm.ko"),
            is_executable: false,
        },
    ];
    pub const INITRAMFS_FILENAME: &'static str = "initramfs.gz";

    pub(crate) async fn create_image(
        &self,
        input_repository: &crate::docker::DockerDaemon,
        enclave_settings: EnclaveSettings,
        user_config: UserConfig,
        env_vars: Vec<String>,
        _sender: std::sync::mpsc::Sender<crate::image::ImageToClean>,
    ) -> Result<SNPEnclavesMeasurements> {
        let work_dir = self.enclave_image_builder.dir.path();

        let file_system_config = self
            .enclave_image_builder
            .create_block_file(input_repository, &user_config)
            .await?;
        info!("Client FS Block file has been created.");

        let is_debug = enclave_settings.is_debug;
        let enable_overlay_filesystem_persistence =
            enclave_settings.enable_overlay_filesystem_persistence;
        let ccm_backend_url = enclave_settings.ccm_backend_url.clone();
        let dsm_configuration = enclave_settings.dsm_configuration.clone();

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

        let output_file_path = work_dir.join(Self::INITRAMFS_FILENAME);
        let output_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output_file_path)
            .map_err(|e| ConverterError {
                message: format!("Failed to create output CPIO file: {:?}", e),
                kind: ConverterErrorKind::EnclaveImageCreation,
            })?;

        info!("Creating initramfs archive...");
        create_initramfs(output_file, &enclave_settings, &enclave_manifest_data).map_err(|e| {
            ConverterError {
                message: format!("Failed to create initramfs: {:?}", e),
                kind: ConverterErrorKind::EnclaveImageCreation,
            }
        })?;

        Ok(SNPEnclavesMeasurements {
            launch_measurement: HexString::new(vec![0; 48]),
        })
    }
}

fn create_initramfs(
    output_file: fs::File,
    enclave_settings: &EnclaveSettings,
    enclave_manifest_data: &[u8],
) -> std::io::Result<()> {
    let run_cmd = GenericEnclaveImageBuilder::enclave_command_string(
        enclave_settings,
        &Path::new(INSTALLATION_DIR),
        "enclave",
    );

    let mut fs_tree = FsTree::new()
        .add_directory("rootfs")
        .add_directory("rootfs/dev")
        .add_directory("rootfs/proc")
        .add_directory("rootfs/run")
        .add_directory("rootfs/sys")
        .add_directory("rootfs/tmp")
        .add_directory("rootfs/bin")
        .add_file("env", Cursor::new(enclave_settings.env_vars.join("\n")))
        .add_file("cmd", Cursor::new(run_cmd))
        .add_executable("init", Cursor::new(EnclaveImageBuilder::INIT_BIN.data))
        .add_file(
            &format!(
                "rootfs{}/{}",
                INSTALLATION_DIR,
                GenericEnclaveImageBuilder::DEFAULT_ENCLAVE_SETTINGS_FILE
            ),
            Cursor::new(enclave_manifest_data.to_vec()),
        );

    // Add enclave, & enclave-startup from resources
    for resource in GenericEnclaveImageBuilder::IMAGE_BUILD_DEPENDENCIES {
        let path = format!("rootfs{}/{}", INSTALLATION_DIR, resource.name);
        fs_tree = fs_tree.add_executable(&path, Cursor::new(resource.data));
    }

    if enclave_settings.gpu_passthrough {
        for module in EnclaveImageBuilder::GPU_MODULES {
            let path = format!("lib/modules/{}", module.name);
            fs_tree = fs_tree.add_file(&path, Cursor::new(module.data));
        }
    }

    Initramfs::from_fs_tree(fs_tree, output_file).map_err(|e| Error::new(ErrorKind::Other, e))?;
    Ok(())
}
