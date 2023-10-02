/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::fs;
use std::io::Write;
use std::path::Path;

use api_model::converter::NitroEnclavesConversionRequestOptions;
use docker_image_reference::Reference as DockerReference;
use log::info;
use tempfile::TempDir;

use crate::docker::DockerUtil;
use crate::file::{BuildContext, DockerCopyArgs, DockerFile, Resource, UnixFile};
use crate::image::ImageWithDetails;
use crate::image_builder::enclave::EnclaveImageBuilder;
use crate::image_builder::{rust_log_env_var, INSTALLATION_DIR, ORIG_ENV_LIST_PATH};
use crate::{file, ConverterError, ConverterErrorKind, Result};

pub(crate) struct ParentImageBuilder<'a> {
    pub(crate) parent_image: String,

    pub(crate) dir: &'a TempDir,

    pub(crate) start_options: NitroEnclavesConversionRequestOptions,
}

impl<'a> ParentImageBuilder<'a> {
    const DEFAULT_CPU_COUNT: u8 = 2;

    const DEFAULT_MEMORY_SIZE: u64 = 2048;

    const STARTUP_SCRIPT_NAME: &'static str = "start-parent.sh";

    const BINARY_NAME: &'static str = "parent";

    const IMAGE_BUILD_DEPENDENCIES: &'static [Resource<'static>] = &[
        file::Resource {
            name: ParentImageBuilder::STARTUP_SCRIPT_NAME,
            data: include_bytes!("../resources/parent/start-parent.sh"),
            is_executable: true,
        },
        file::Resource {
            name: ParentImageBuilder::BINARY_NAME,
            data: include_bytes!("../resources/parent/parent"),
            is_executable: true,
        },
    ];

    const IMAGE_COPY_DEPENDENCIES: &'static [&'static str] = &[
        ParentImageBuilder::STARTUP_SCRIPT_NAME,
        ParentImageBuilder::BINARY_NAME,
        EnclaveImageBuilder::ENCLAVE_FILE_NAME,
        EnclaveImageBuilder::BLOCK_FILE_OUT,
    ];

    pub(crate) async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        image_reference: DockerReference<'a>,
    ) -> Result<ImageWithDetails<'a>> {
        let build_context = BuildContext::new(&self.dir.path()).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        self.move_enclave_files_into_build_context(&build_context.path())?;

        self.create_requisites(&build_context).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })?;
        info!("Parent prerequisites have been created!");

        let build_context_archive_file = build_context
            .package_into_archive(&self.dir.path().join("parent-build-context.tar"))
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

    fn move_enclave_files_into_build_context(&self, build_context_dir: &Path) -> Result<()> {
        fn move_file(from: &Path, to: &Path) -> Result<()> {
            fs::rename(from, to).map_err(|message| ConverterError {
                message: format!(
                    "Failed moving file {} into build context {}. {:?}",
                    from.display(),
                    to.display(),
                    message
                ),
                kind: ConverterErrorKind::RequisitesCreation,
            })
        }

        move_file(
            &self.dir.path().join(EnclaveImageBuilder::ENCLAVE_FILE_NAME),
            &build_context_dir.join(EnclaveImageBuilder::ENCLAVE_FILE_NAME),
        )?;

        move_file(
            &self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_OUT),
            &build_context_dir.join(EnclaveImageBuilder::BLOCK_FILE_OUT),
        )
    }

    fn create_requisites(&self, build_context: &BuildContext) -> std::result::Result<(), String> {
        let copy_items: Vec<String> = ParentImageBuilder::IMAGE_COPY_DEPENDENCIES
            .iter()
            .map(|e| e.to_string())
            .collect();

        let docker_file = self.docker_file_contents(copy_items);

        build_context.create_docker_file(&docker_file)?;

        build_context.create_resources(ParentImageBuilder::IMAGE_BUILD_DEPENDENCIES)?;

        let startup_script_path = build_context.path().join(ParentImageBuilder::STARTUP_SCRIPT_NAME);

        self.append_start_enclave_command(&startup_script_path)?;

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

        let run_parent_cmd = Path::new(INSTALLATION_DIR).join("start-parent.sh").display().to_string();

        let log_env = rust_log_env_var("parent");
        let cpu_count_env = self.cpu_count_env_var();
        let mem_size_env = self.mem_size_env_var();
        let eos_debug_env = self.eos_debug_env_var();

        let env_vars = [log_env, cpu_count_env, mem_size_env, eos_debug_env];

        let abs_orig_env_list_path = Path::new(INSTALLATION_DIR).join(ORIG_ENV_LIST_PATH).display().to_string();
        let save_envs_run_command = format!("printenv > {}", abs_orig_env_list_path);

        let from = self.parent_image.clone();

        DockerFile {
            from,
            add: Some(add),
            env: env_vars.to_vec(),
            run: Some(save_envs_run_command),
            cmd: None,
            entrypoint: Some(run_parent_cmd),
        }
    }

    fn append_start_enclave_command(&self, startup_script_path: &Path) -> std::result::Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(startup_script_path)
            .map_err(|err| format!("Failed to open parent startup script {:?}", err))?;

        let start_enclave_command = self.start_enclave_command();

        file.write_all(start_enclave_command.as_bytes())
            .map_err(|err| format!("Failed to write to file {:?}", err))?;

        file.set_execute()
            .map_err(|err| format!("Cannot change permissions for a file {:?}", err))?;

        Ok(())
    }

    fn start_enclave_command(&self) -> String {
        let install_path = Path::new(INSTALLATION_DIR);
        let parent_bin = install_path.join("parent");
        // We start the parent side of the vsock proxy before running the enclave because we want it running
        // first. The nitro-cli run-enclave command exits after starting the enclave, so the parent process
        // of our container will stay running as long as the parent process stays running.
        format!(
            "\n\
             # Parent startup code \n\
             {} \"$@\" ",
            parent_bin.display()
        )
    }

    fn eos_debug_env_var(&self) -> String {
        format!("ENCLAVEOS_DEBUG={}", {
            if cfg!(debug_assertions) {
                "debug"
            } else {
                ""
            }
        })
    }

    fn cpu_count_env_var(&self) -> String {
        format!(
            "CPU_COUNT={}",
            self.start_options.cpu_count.unwrap_or(ParentImageBuilder::DEFAULT_CPU_COUNT)
        )
    }

    fn mem_size_env_var(&self) -> String {
        format!(
            "MEM_SIZE={}",
            self.start_options
                .mem_size
                .as_ref()
                .map(|e| e.to_mb())
                .unwrap_or(ParentImageBuilder::DEFAULT_MEMORY_SIZE)
        )
    }
}
