/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::Path;

use api_model::nitro::NitroEnclavesConversionRequestOptions;
use docker_image_reference::Reference as DockerReference;
use log::info;

use crate::docker::DockerUtil;
use crate::file::{BuildContext, DockerCopyArgs, DockerFile};
use crate::image::ImageWithDetails;
use crate::image_builder::enclave::EnclaveImageBuilder;
use crate::image_builder::{rust_log_env_var, INSTALLATION_DIR, ORIG_ENV_LIST_PATH};
use crate::{file, ConverterError, ConverterErrorKind, Result};

pub(crate) struct ParentImageBuilder<'a> {
    pub(crate) parent_image_builder: crate::image_builder::parent::ParentImageBuilder<'a>,
    pub(crate) start_options: NitroEnclavesConversionRequestOptions,
}

impl<'a> ParentImageBuilder<'a> {
    pub(crate) const IMAGE_COPY_DEPENDENCIES: &'static [&'static str] = &[
        crate::image_builder::parent::ParentImageBuilder::STARTUP_SCRIPT_NAME,
        crate::image_builder::parent::ParentImageBuilder::BINARY_NAME,
        crate::image_builder::enclave::nitro::EnclaveImageBuilder::ENCLAVE_FILE_NAME,
        EnclaveImageBuilder::BLOCK_FILE_OUT,
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

        self.parent_image_builder
            .move_enclave_files_into_build_context(
                &build_context.path(),
                crate::image_builder::enclave::nitro::EnclaveImageBuilder::ENCLAVE_FILE_NAME,
            )?;

        self.create_requisites(&build_context, Self::IMAGE_COPY_DEPENDENCIES)
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
        copy_dependencies: &'static [&'static str],
    ) -> std::result::Result<(), String> {
        let copy_items: Vec<String> = copy_dependencies.iter().map(|e| e.to_string()).collect();

        let docker_file = self.docker_file_contents(copy_items);

        build_context.create_docker_file(&docker_file)?;

        build_context.create_resources(
            crate::image_builder::parent::ParentImageBuilder::IMAGE_BUILD_DEPENDENCIES,
        )?;

        let startup_script_path = build_context
            .path()
            .join(crate::image_builder::parent::ParentImageBuilder::STARTUP_SCRIPT_NAME);

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
        let eos_debug_env = crate::image_builder::parent::ParentImageBuilder::eos_debug_env_var();

        let env_vars = [log_env, cpu_count_env, mem_size_env, eos_debug_env];

        let abs_orig_env_list_path = Path::new(INSTALLATION_DIR)
            .join(ORIG_ENV_LIST_PATH)
            .display()
            .to_string();
        let save_envs_run_command = format!("printenv > {}", abs_orig_env_list_path);

        let from = self.parent_image_builder.parent_image.clone();

        DockerFile {
            from,
            add: Some(add),
            env: env_vars.to_vec(),
            run: Some(save_envs_run_command),
            cmd: None,
            entrypoint: Some(vec![
                run_parent_cmd,
                "--platform".to_string(),
                "nitro".to_string(),
            ]),
        }
    }

    fn cpu_count_env_var(&self) -> String {
        format!(
            "CPU_COUNT={}",
            self.start_options
                .cpu_count
                .unwrap_or(crate::image_builder::parent::ParentImageBuilder::DEFAULT_CPU_COUNT)
        )
    }

    fn mem_size_env_var(&self) -> String {
        format!(
            "MEM_SIZE={}",
            self.start_options
                .mem_size
                .as_ref()
                .map(|e| e.to_mb())
                .unwrap_or(crate::image_builder::parent::ParentImageBuilder::DEFAULT_MEMORY_SIZE)
        )
    }
}
