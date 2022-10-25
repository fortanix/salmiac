use docker_image_reference::Reference as DockerReference;
use log::info;
use tempfile::TempDir;

use crate::docker::DockerUtil;
use crate::file::{DockerCopyArgs, DockerFile, Resource, UnixFile};
use crate::Result;
use crate::{file, ConverterError, ConverterErrorKind};
use api_model::NitroEnclavesConversionRequestOptions;

use crate::image::ImageWithDetails;
use crate::image_builder::enclave::EnclaveImageBuilder;
use crate::image_builder::{rust_log_env_var, INSTALLATION_DIR};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

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
    ];

    pub(crate) async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        image_reference: DockerReference<'a>,
    ) -> Result<ImageWithDetails<'a>> {
        let build_context_dir = self.create_build_context_dir()?;

        let block_file_exists = self.move_enclave_files_into_build_context(&build_context_dir)?;

        self.create_requisites(&build_context_dir, block_file_exists)
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;
        info!("Parent prerequisites have been created!");

        let result = docker_util
            .create_image(image_reference, &build_context_dir)
            .await
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::ParentImageCreation,
            })?;

        info!("Parent image has been created!");

        Ok(result)
    }

    fn create_build_context_dir(&self) -> Result<PathBuf> {
        let result = self.dir.path().join("parent-build-context");

        fs::create_dir(&result).map_err(|err| ConverterError {
            message: format!("Failed creating dir {}. {:?}", result.display(), err),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        Ok(result)
    }

    fn move_enclave_files_into_build_context(&self, build_context_dir: &Path) -> Result<bool> {
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

        let block_file = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_OUT);
        if block_file.exists() {
            move_file(&block_file, &build_context_dir.join(EnclaveImageBuilder::BLOCK_FILE_OUT))?;

            let rw_block_file = self.dir.path().join(EnclaveImageBuilder::RW_BLOCK_FILE_OUT);
            move_file(
                &rw_block_file,
                &build_context_dir.join(EnclaveImageBuilder::RW_BLOCK_FILE_OUT),
            )?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn create_requisites(&self, dir: &Path, block_file_exists: bool) -> std::result::Result<(), String> {
        let mut docker_file = file::create_docker_file(dir)?;

        let mut copy_items = ParentImageBuilder::IMAGE_COPY_DEPENDENCIES.to_vec();

        if block_file_exists {
            copy_items.push(EnclaveImageBuilder::BLOCK_FILE_OUT);
            copy_items.push(EnclaveImageBuilder::RW_BLOCK_FILE_OUT);
        }

        self.populate_docker_file(&mut docker_file, &copy_items)?;

        if cfg!(debug_assertions) {
            file::log_docker_file(dir)?;
        }

        file::create_resources(ParentImageBuilder::IMAGE_BUILD_DEPENDENCIES, dir)?;
        let startup_script_path = dir.join(ParentImageBuilder::STARTUP_SCRIPT_NAME);

        self.append_start_enclave_command(&startup_script_path)?;

        if cfg!(debug_assertions) {
            file::log_file(&startup_script_path)?;
        }

        Ok(())
    }

    fn populate_docker_file(&self, file: &mut fs::File, copy_items: &[&str]) -> std::result::Result<(), String> {
        let add = DockerCopyArgs {
            items: &copy_items,
            destination: INSTALLATION_DIR.to_string() + "/",
        };

        let run_parent_cmd = Path::new(INSTALLATION_DIR).join("start-parent.sh").display().to_string();

        let log_env = rust_log_env_var("parent");
        let cpu_count_env = self.cpu_count_env_var();
        let mem_size_env = self.mem_size_env_var();
        let eos_debug_env = self.eos_debug_env_var();

        let env_vars = [
            log_env.as_str(),
            cpu_count_env.as_str(),
            mem_size_env.as_str(),
            eos_debug_env.as_str(),
        ];

        let docker_file = DockerFile {
            from: &self.parent_image,
            add: Some(add),
            env: &env_vars,
            cmd: None,
            entrypoint: Some(&run_parent_cmd),
        };

        file.write_all(docker_file.to_string().as_bytes())
            .map_err(|err| format!("Failed to write to Dockerfile {:?}", err))
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

        // Construct two sets of commands for the parent start up script:
        // dbg_cmd runs the enclave in debug mode and prints enclave logs
        // to console. cmd simply runs the enclave with no additional
        // logging
        let (dbg_cmd, cmd) = self.get_nitro_run_commands(&install_path);
        // We start the parent side of the vsock proxy before running the enclave because we want it running
        // first. The nitro-cli run-enclave command exits after starting the enclave, so we foreground proxy
        // parent process so our container will stay running as long as the parent process stays running.
        format!(
            "\n\
             # Parent startup code \n\
             {} --vsock-port 5006 \"$@\" & \n\
             dbg_cmd=\"{}\" \n\
             cmd=\"{}\" \n\
             if [ -n \"$ENCLAVEOS_DEBUG\" ] ; then eval \"$dbg_cmd\" ; else eval \"$cmd\" ; fi; \n\
             fg \n",
            parent_bin.display(),
            dbg_cmd,
            cmd
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

    fn get_nitro_run_commands(&self, install_path: &Path) -> (String, String) {
        let nitro_file_path = install_path.join(EnclaveImageBuilder::ENCLAVE_FILE_NAME);
        let sanitized_nitro_file = format!("'{}'", nitro_file_path.display());

        let nitro_run_cmd = format!(
            "nitro-cli run-enclave --eif-path {} --cpu-count \
                                           $CPU_COUNT --memory $MEM_SIZE",
            sanitized_nitro_file
        );

        // --enclave-name here is the name of the .eif file which is fixed to "enclave"
        let dbg_cmd = format!(
            "{} --debug-mode \n\
            nitro-cli console --enclave-name enclave ",
            nitro_run_cmd
        );
        return (dbg_cmd, nitro_run_cmd);
    }
}
