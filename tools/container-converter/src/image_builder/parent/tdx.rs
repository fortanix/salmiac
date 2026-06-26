/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::{Path, PathBuf};

use api_model::tdx::TDXEnclavesConversionRequestOptions;
use docker_image_reference::Reference as DockerReference;
use log::info;

use crate::docker::DockerUtil;
use crate::file::{BuildContext, DockerCopyArgs, DockerFile};
use crate::image::ImageWithDetails;
use crate::image_builder::enclave::tdx::EnclaveImageBuilder as TdxEnclaveImageBuilder;
use crate::image_builder::enclave::GenericEnclaveImageBuilder;
use crate::image_builder::parent::ParentImageBuilder as GenericParentImageBuilder;
use crate::image_builder::{rust_log_env_var, INSTALLATION_DIR, ORIG_ENV_LIST_PATH};
use crate::{file, ConverterError, ConverterErrorKind, Result};

use super::move_file;

pub(crate) const BLOBS_SUBDIR_GPU_ENABLED: &'static str = "kernel_enabled_gpu";
pub(crate) const BLOBS_SUBDIR_GPU_DISABLED: &'static str = "kernel_disabled_gpu";

pub(crate) struct ParentImageBuilder<'a> {
    pub(crate) parent_image_builder: crate::image_builder::parent::ParentImageBuilder<'a>,
    pub(crate) start_options: TDXEnclavesConversionRequestOptions,
}

impl<'a> ParentImageBuilder<'a> {
    pub(crate) const IMAGE_COPY_DEPENDENCIES: &'static [&'static str] = &[
        GenericParentImageBuilder::STARTUP_SCRIPT_NAME,
        GenericParentImageBuilder::BINARY_NAME,
        TdxEnclaveImageBuilder::INITRAMFS_FILENAME,
        GenericEnclaveImageBuilder::BLOCK_FILE_OUT,
    ];

    pub(crate) async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        image_reference: DockerReference<'a>,
    ) -> Result<ImageWithDetails<'a>> {
        let build_context =
            BuildContext::new(&self.parent_image_builder.dir.path()).map_err(|message| {
                ConverterError {
                    message,
                    kind: ConverterErrorKind::RequisitesCreation,
                }
            })?;

        // Move initramfs build by enclave image builder to build context.
        self.parent_image_builder
            .move_enclave_files_into_build_context(
                build_context.path(),
                TdxEnclaveImageBuilder::INITRAMFS_FILENAME,
            )?;

        let blob_filenames = self.move_blobs_into_build_context(&build_context)?;
        let mut copy_dependencies: Vec<String> = Self::IMAGE_COPY_DEPENDENCIES
            .iter()
            .map(|e| e.to_string())
            .collect();
        copy_dependencies.extend(blob_filenames);

        self.create_requisites(&build_context, &copy_dependencies)
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;
        info!("Parent prerequisites have been created!");

        let build_context_archive_file = build_context
            .package_into_archive(
                &self
                    .parent_image_builder
                    .dir
                    .path()
                    .join("parent-build-context.tar"),
            )
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        let result = docker_util
            .create_image_from_archive(image_reference, build_context_archive_file)
            .await
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::ParentImageCreation,
            })?;

        info!("Parent image has been created!");

        Ok(result)
    }

    fn create_requisites(
        &self,
        build_context: &BuildContext,
        copy_dependencies: &[String],
    ) -> std::result::Result<(), String> {
        let docker_file = self.docker_file_contents(copy_dependencies.to_vec());

        build_context.create_docker_file(&docker_file)?;

        build_context.create_resources(GenericParentImageBuilder::IMAGE_BUILD_DEPENDENCIES)?;

        let startup_script_path = build_context
            .path()
            .join(GenericParentImageBuilder::STARTUP_SCRIPT_NAME);

        self.parent_image_builder
            .append_start_enclave_command(&startup_script_path)?;

        if cfg!(debug_assertions) {
            file::log_file(&startup_script_path)?;
        }

        Ok(())
    }

    fn docker_file_contents(&self, items: Vec<String>) -> DockerFile {
        let add = DockerCopyArgs {
            items,
            destination: INSTALLATION_DIR.to_string() + "/",
        };

        let run_parent_cmd = Path::new(INSTALLATION_DIR)
            .join("start-parent.sh")
            .display()
            .to_string();

        let log_env = rust_log_env_var("parent");
        let cpu_count_env = self.cpu_count_env_var();
        let mem_size_env = self.mem_size_env_var();
        let eos_debug_env = GenericParentImageBuilder::eos_debug_env_var();

        let env_vars = vec![log_env, cpu_count_env, mem_size_env, eos_debug_env];

        let abs_orig_env_list_path = Path::new(INSTALLATION_DIR)
            .join(ORIG_ENV_LIST_PATH)
            .display()
            .to_string();
        let save_envs_run_command = format!("printenv > {}", abs_orig_env_list_path);

        let from = self.parent_image_builder.parent_image.clone();

        DockerFile {
            from,
            add: Some(add),
            env: env_vars,
            run: Some(save_envs_run_command),
            cmd: None,
            entrypoint: Some(vec![
                run_parent_cmd,
                "--platform".to_string(),
                "tdx".to_string(),
            ]),
        }
    }

    fn cpu_count_env_var(&self) -> String {
        let cpu_count = if self.start_options.cpu_count == 0 {
            GenericParentImageBuilder::DEFAULT_CPU_COUNT
        } else {
            self.start_options.cpu_count
        };
        format!("CPU_COUNT={}", cpu_count)
    }

    fn mem_size_env_var(&self) -> String {
        format!(
            "MEM_SIZE={}",
            self.start_options
                .mem_size
                .as_ref()
                .map(|e| e.to_mb())
                .unwrap_or(GenericParentImageBuilder::DEFAULT_MEMORY_SIZE)
        )
    }

    // Moves blobs located at system to build context and returns filenames only
    fn move_blobs_into_build_context(&self, build_context: &BuildContext) -> Result<Vec<String>> {
        let blobs = self.collect_blob_paths()?;
        let mut filenames = Vec::with_capacity(blobs.len());
        for blob in blobs {
            let filename = blob
                .file_name()
                .and_then(|f| f.to_str())
                .ok_or(ConverterError {
                    message: format!("Invalid path: {}", blob.display()),
                    kind: ConverterErrorKind::RequisitesCreation,
                })?;
            let dest = build_context.path().join(filename);
            move_file(blob.as_path(), &dest)?;
            filenames.push(filename.to_owned());
        }

        Ok(filenames)
    }

    fn collect_blob_paths(&self) -> Result<Vec<PathBuf>> {
        let mut ret = Vec::new();
        let mut blobs_dir = PathBuf::from(format!("{}/blobs", INSTALLATION_DIR));

        {
            blobs_dir.push("OVMF.amdsev.fd");
            let blob_path = blobs_dir.clone();
            if !blob_path.exists() {
                return Err(ConverterError {
                    message: format!("OVMF file could not be found at: {}", blob_path.display()),
                    kind: ConverterErrorKind::RequisitesCreation,
                });
            }
            ret.push(blob_path);
            blobs_dir.pop();
        }

        if self.start_options.enable_gpu_passthrough.unwrap_or(false) {
            blobs_dir.push(BLOBS_SUBDIR_GPU_ENABLED);
        } else {
            blobs_dir.push(BLOBS_SUBDIR_GPU_DISABLED);
        }

        let kernel_blobs = vec!["bzImage", "bzImage.config"];
        for blob in kernel_blobs {
            blobs_dir.push(blob);
            let blob_path = blobs_dir.clone();
            if !blob_path.exists() {
                return Err(ConverterError {
                    message: format!("Blob {} could not be found!", blob_path.display()),
                    kind: ConverterErrorKind::RequisitesCreation,
                });
            }
            ret.push(blob_path);
            blobs_dir.pop();
        }

        Ok(ret)
    }
}
