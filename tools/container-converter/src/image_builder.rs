use async_process::{Command, Stdio};
use docker_image_reference::Reference as DockerReference;
use log::{debug, error, info};
use tar::Archive;
use tempfile::TempDir;

use crate::file::{DockerCopyArgs, DockerFile, Resource, UnixFile};
use crate::image::{create_nitro_image, DockerUtil, ImageWithDetails, PCRList};
use crate::{file, ConverterError, ConverterErrorKind};
use crate::{ImageKind, ImageToClean, Result};
use api_model::shared::{EnclaveManifest, FileSystemConfig, UserConfig};
use api_model::{ConverterOptions, NitroEnclavesConversionRequestOptions};

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc::Sender;

pub struct EnclaveImageBuilder<'a> {
    pub client_image_reference: &'a DockerReference<'a>,

    pub dir: &'a TempDir,

    pub enclave_base_image: Option<String>,
}

pub struct EnclaveSettings {
    user_name: String,

    env_vars: Vec<String>,

    is_debug: bool,
}

impl EnclaveSettings {
    pub fn new(input_image: &ImageWithDetails<'_>, converter_options: &ConverterOptions) -> Self {
        let env_vars = {
            let mut result = input_image.details.config.env.as_ref().map(|e| e.clone()).unwrap_or(vec![]);

            // Docker `ENV` assigns environment variables by the order of definition, thus making
            // latest definition of the same variable override previous definition.
            // We exploit this logic to override variables from the `input_image` with the values from `conversion_request`
            // by adding all `conversion_request` variables to the end of `env_vars` vector.
            for request_env in &converter_options.env_vars {
                result.push(request_env.clone());
            }

            result
        };

        EnclaveSettings {
            user_name: input_image.details.config.user.clone(),
            env_vars,
            is_debug: converter_options.debug.unwrap_or(false),
        }
    }
}

pub struct EnclaveBuilderResult {
    pub pcr_list: PCRList,
}

const INSTALLATION_DIR: &'static str = "/opt/fortanix/enclave-os";

impl<'a> EnclaveImageBuilder<'a> {
    pub const ENCLAVE_FILE_NAME: &'static str = "enclave.eif";

    const DEFAULT_ENCLAVE_SETTINGS_FILE: &'static str = "enclave-settings.json";

    const BLOCK_FILE_SCRIPT_NAME: &'static str = "create-block-file.sh";

    const BLOCK_FILE_INPUT_DIR: &'static str = "enclave-fs";

    const BLOCK_FILE_MOUNT_DIR: &'static str = "block-file-mount";

    pub const BLOCK_FILE_OUT: &'static str = "Blockfile.ext4";

    pub const RW_BLOCK_FILE_OUT: &'static str = "Blockfile-rw.ext4";

    // 256 MB converted to bytes
    pub const RW_BLOCK_FILE_DEFAULT_SIZE: u64 = 256 * 1024 * 1024;

    pub async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        enclave_settings: EnclaveSettings,
        user_config: UserConfig,
        images_to_clean_snd: Sender<ImageToClean>,
    ) -> Result<EnclaveBuilderResult> {
        let build_context_dir = self.create_build_context_dir()?;
        let is_debug = enclave_settings.is_debug;

        self.create_requisites(enclave_settings, &build_context_dir)
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        let fs_root_hash = match &self.enclave_base_image {
            Some(_) => {
                let root_hash = self.create_block_file(docker_util).await?;
                info!("Client FS Block file has been created.");

                self.create_rw_block_file().await?;
                info!("RW Block file has been created.");

                Some(root_hash)
            }
            _ => None,
        };

        let enclave_manifest = EnclaveManifest {
            user_config,
            file_system_config: fs_root_hash,
            is_debug,
        };

        self.create_manifest_file(enclave_manifest, &build_context_dir)?;

        info!("Enclave build prerequisites have been created!");

        let enclave_image_str = self.enclave_image();
        let enclave_image_reference = DockerReference::from_str(&enclave_image_str).map_err(|message| ConverterError {
            message: format!("Failed to create enclave image reference. {:?}", message),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        // This image is made temporary because it is only used by nitro-cli to create an `.eif` file.
        // After nitro-cli finishes we can safely reclaim it.
        let result = create_image(
            docker_util,
            enclave_image_reference,
            &build_context_dir,
            ConverterErrorKind::EnclaveImageCreation,
        )
        .await
        .map(|e| e.make_temporary(ImageKind::Intermediate, images_to_clean_snd))?;

        let nitro_measurements = {
            let nitro_image_path = &self.dir.path().join(EnclaveImageBuilder::ENCLAVE_FILE_NAME);

            create_nitro_image(&result.image.reference, &nitro_image_path).await?
        };

        info!("Nitro image has been created!");

        Ok(EnclaveBuilderResult {
            pcr_list: nitro_measurements.pcr_list,
        })
    }

    fn create_build_context_dir(&self) -> Result<PathBuf> {
        let result = self.dir.path().join("enclave-build-context");

        fs::create_dir(&result).map_err(|err| ConverterError {
            message: format!("Failed creating dir {}. {:?}", result.display(), err),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        Ok(result)
    }

    fn create_manifest_file(&self, enclave_manifest: EnclaveManifest, dir: &Path) -> Result<()> {
        let data = serde_json::to_vec(&enclave_manifest).map_err(|err| ConverterError {
            message: format!("Failed serializing enclave settings file. {:?}", err),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        let resource = [Resource {
            name: "enclave-settings.json",
            data: &data,
            is_executable: false,
        }];

        file::create_resources(&resource, dir).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })
    }

    async fn create_rw_block_file(&self) -> Result<()> {
        let block_file_out_path = self.dir.path().join(EnclaveImageBuilder::RW_BLOCK_FILE_OUT);

        let block_file = fs::File::create(&block_file_out_path).map_err(|err| ConverterError {
            message: format!("Failed creating RW block file {}. {:?}", block_file_out_path.display(), err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        block_file
            .set_len(EnclaveImageBuilder::RW_BLOCK_FILE_DEFAULT_SIZE)
            .map_err(|err| ConverterError {
                message: format!(
                    "Failed truncating RW block file {} to size {}. {:?}",
                    block_file_out_path.display(),
                    EnclaveImageBuilder::RW_BLOCK_FILE_DEFAULT_SIZE,
                    err
                ),
                kind: ConverterErrorKind::BlockFileCreation,
            })?;

        Ok(())
    }

    async fn create_block_file(&self, docker_util: &dyn DockerUtil) -> Result<FileSystemConfig> {
        let block_file_script = [Resource {
            name: EnclaveImageBuilder::BLOCK_FILE_SCRIPT_NAME,
            data: include_bytes!("resources/fs/configure"),
            is_executable: true,
        }];

        file::create_resources(&block_file_script, self.dir.path()).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        let block_file_input_dir = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_INPUT_DIR);
        let block_file_mount_dir = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_MOUNT_DIR);

        fs::create_dir(&block_file_input_dir).map_err(|err| ConverterError {
            message: format!("Failed creating dir {}. {:?}", block_file_input_dir.display(), err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        fs::create_dir(&block_file_mount_dir).map_err(|err| ConverterError {
            message: format!("Failed creating dir {}. {:?}", block_file_mount_dir.display(), err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        self.export_image_file_system(docker_util, &block_file_input_dir).await?;

        let result = {
            let block_file_out = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_OUT);
            let args = [
                block_file_input_dir.as_os_str(),
                block_file_mount_dir.as_os_str(),
                block_file_out.as_os_str(),
            ];
            let block_file_script_path = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_SCRIPT_NAME);

            run_subprocess(block_file_script_path.as_os_str(), &args)
                .await
                .map_err(|message| ConverterError {
                    message,
                    kind: ConverterErrorKind::BlockFileCreation,
                })?
        };

        EnclaveImageBuilder::create_file_system_config(&result)
    }

    fn create_file_system_config(stdout: &str) -> Result<FileSystemConfig> {
        fn field_value(stdout: &str, field_start: usize) -> Option<&str> {
            stdout[field_start..]
                .find("\n")
                .map(|field_end| stdout[field_start..field_start + field_end].trim())
        }

        fn extract_value<'a>(stdout: &'a str, field_header: &str) -> Result<&'a str> {
            stdout
                .find(field_header)
                .and_then(|pos| field_value(stdout, pos + field_header.len()))
                .ok_or(ConverterError {
                    message: format!("Failed to find {} in stdout. Stdout: {}", field_header, stdout),
                    kind: ConverterErrorKind::BlockFileCreation,
                })
        }

        let root_hash = extract_value(stdout, "Root hash:")?;
        let raw_hash_offset = extract_value(stdout, "Hash offset:")?;

        let hash_offset = u64::from_str(raw_hash_offset).map_err(|err| ConverterError {
            message: format!("Failed to convert hash offset {} to int. {:?}", raw_hash_offset, err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        Ok(FileSystemConfig {
            root_hash: root_hash.to_string(),
            hash_offset,
        })
    }

    async fn export_image_file_system(&self, docker_util: &dyn DockerUtil, out_dir: &Path) -> Result<()> {
        let client_file_system = docker_util
            .export_image_file_system(&self.client_image_reference)
            .await
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::ImageFileSystemExport,
            })?;

        let mut tar = Archive::new(&client_file_system as &[u8]);

        tar.unpack(out_dir).map_err(|err| ConverterError {
            message: format!(
                "Failed unpacking client fs archive {}. {:?}",
                EnclaveImageBuilder::BLOCK_FILE_INPUT_DIR,
                err
            ),
            kind: ConverterErrorKind::ImageFileSystemExport,
        })
    }

    fn enclave_image(&self) -> String {
        let new_tag = self
            .client_image_reference
            .tag()
            .map(|e| e.to_string() + "-enclave")
            .unwrap_or("enclave".to_string());

        self.client_image_reference.name().to_string() + ":" + &new_tag
    }

    const IMAGE_BUILD_DEPENDENCIES: &'static [Resource<'static>] = &[
        Resource {
            name: "enclave",
            data: include_bytes!("resources/enclave/enclave"),
            is_executable: true,
        },
        Resource {
            name: "enclave-startup",
            data: include_bytes!("resources/enclave/enclave-startup"),
            is_executable: true,
        },
    ];

    const IMAGE_COPY_DEPENDENCIES: &'static [&'static str] = &["enclave", "enclave-settings.json", "enclave-startup"];

    fn create_requisites(&self, enclave_settings: EnclaveSettings, dir: &Path) -> std::result::Result<(), String> {
        let mut docker_file = file::create_docker_file(dir)?;

        self.populate_docker_file(&mut docker_file, enclave_settings)?;

        if cfg!(debug_assertions) {
            file::log_docker_file(dir)?;
        }

        file::create_resources(EnclaveImageBuilder::IMAGE_BUILD_DEPENDENCIES, dir)?;

        Ok(())
    }

    fn populate_docker_file(&self, file: &mut fs::File, enclave_settings: EnclaveSettings) -> std::result::Result<(), String> {
        let install_dir_path = Path::new(INSTALLATION_DIR);

        let add = DockerCopyArgs {
            items: EnclaveImageBuilder::IMAGE_COPY_DEPENDENCIES,
            destination: INSTALLATION_DIR.to_string() + "/",
        };

        let run_enclave_cmd = {
            let enclave_bin = install_dir_path.join("enclave");

            let enclave_settings_file = install_dir_path.join(EnclaveImageBuilder::DEFAULT_ENCLAVE_SETTINGS_FILE);

            let user_name = {
                if let Some(pos) = enclave_settings.user_name.find(":") {
                    &enclave_settings.user_name[..pos]
                } else {
                    &enclave_settings.user_name
                }
            };

            // Quick fix for: https://fortanix.atlassian.net/browse/SALM-94
            // Sets the home variable specifically for applications that require it to run
            let switch_user_cmd = if user_name != "" && user_name != "root" {
                format!("export HOME=/home/{};", user_name)
            } else {
                String::new()
            };

            format!(
                "{} {} --vsock-port 5006 --settings-path {}",
                switch_user_cmd,
                enclave_bin.display(),
                enclave_settings_file.display()
            )
        };

        let client_image = &self.client_image_reference.to_string();
        let from = match &self.enclave_base_image {
            Some(e) => e,
            _ => client_image,
        };

        let mut env = enclave_settings.env_vars;
        env.push(rust_log_env_var("enclave"));

        let docker_file = DockerFile {
            from,
            add: Some(add),
            env: &env,
            cmd: Some(&run_enclave_cmd),
            entrypoint: None,
        };

        file.write_all(docker_file.to_string().as_bytes())
            .map_err(|err| format!("Failed to write to Dockerfile {:?}", err))
    }
}

pub struct ParentImageBuilder<'a> {
    pub parent_image: String,

    pub dir: &'a TempDir,

    pub start_options: NitroEnclavesConversionRequestOptions,
}

impl<'a> ParentImageBuilder<'a> {
    const DEFAULT_CPU_COUNT: u8 = 2;

    const DEFAULT_MEMORY_SIZE: u64 = 2048;

    const STARTUP_SCRIPT_NAME: &'static str = "start-parent.sh";

    const BINARY_NAME: &'static str = "parent";

    fn create_build_context_dir(&self) -> Result<PathBuf> {
        let result = self.dir.path().join("parent-build-context");

        fs::create_dir(&result).map_err(|err| ConverterError {
            message: format!("Failed creating dir {}. {:?}", result.display(), err),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        Ok(result)
    }

    pub async fn create_image(
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

        let result = create_image(
            docker_util,
            image_reference,
            &build_context_dir,
            ConverterErrorKind::ParentImageCreation,
        )
        .await?;

        info!("Parent image has been created!");

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

    const IMAGE_BUILD_DEPENDENCIES: &'static [Resource<'static>] = &[
        file::Resource {
            name: ParentImageBuilder::STARTUP_SCRIPT_NAME,
            data: include_bytes!("resources/parent/start-parent.sh"),
            is_executable: true,
        },
        file::Resource {
            name: ParentImageBuilder::BINARY_NAME,
            data: include_bytes!("resources/parent/parent"),
            is_executable: true,
        },
    ];

    const IMAGE_COPY_DEPENDENCIES: &'static [&'static str] = &[
        ParentImageBuilder::STARTUP_SCRIPT_NAME,
        ParentImageBuilder::BINARY_NAME,
        EnclaveImageBuilder::ENCLAVE_FILE_NAME,
    ];

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

async fn create_image<'a>(
    docker_util: &dyn DockerUtil,
    image: DockerReference<'a>,
    dir: &Path,
    kind: ConverterErrorKind,
) -> Result<ImageWithDetails<'a>> {
    docker_util
        .create_image(dir, &image)
        .await
        .map_err(|message| ConverterError { message, kind })?;

    let details = docker_util.get_image(&image).await.map_err(|message| ConverterError {
        message,
        kind: ConverterErrorKind::ImageGet,
    })?;

    Ok(ImageWithDetails {
        reference: image,
        details,
    })
}

fn rust_log_env_var(project_name: &str) -> String {
    let log_level = if cfg!(debug_assertions) { "debug" } else { "info" };

    format!("RUST_LOG={}={}", project_name, log_level)
}

pub async fn run_subprocess(subprocess_path: &OsStr, args: &[&OsStr]) -> std::result::Result<String, String> {
    let mut command = Command::new(subprocess_path);

    command.stdout(Stdio::piped());
    command.args(args);

    debug!("Running subprocess {:?} {:?}", subprocess_path, args);
    let process = command
        .spawn()
        .map_err(|err| format!("Failed to run subprocess {:?}. {:?}. Args {:?}", subprocess_path, err, args))?;

    let output = process.output().await.map_err(|err| {
        format!(
            "Error while waiting for subprocess {:?} to finish: {:?}. Args {:?}",
            subprocess_path, err, args
        )
    })?;

    if !output.status.success() {
        let result = String::from_utf8_lossy(&output.stderr);

        error!("status: {}", output.status);
        error!("stderr: {}", result);

        Err(format!(
            "External process {:?} exited with {}. Stderr: {}",
            subprocess_path, output.status, result
        ))
    } else {
        let result = String::from_utf8_lossy(&output.stdout);

        info!("status: {}", output.status);
        info!("stdout: {}", result);

        Ok(result.to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::image::{DockerUtil, ImageWithDetails};
    use crate::image_builder::EnclaveSettings;
    use crate::EnclaveImageBuilder;
    use api_model::ConverterOptions;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use docker_image_reference::Reference;
    use docker_image_reference::Reference as DockerReference;
    use shiplift::container::ContainerCreateInfo;
    use shiplift::image::ContainerConfig;
    use shiplift::image::ImageDetails;
    use std::fs;
    use std::io::Read;
    use std::path::Path;
    use tar::{Builder, Header};
    use tempfile::TempDir;

    struct TestDockerDaemon {}

    #[async_trait]
    impl DockerUtil for TestDockerDaemon {
        async fn get_image(&self, _image: &DockerReference<'_>) -> Result<ImageDetails, String> {
            todo!()
        }

        async fn load_image(&self, _tar_path: &str) -> Result<(), String> {
            todo!()
        }

        async fn push_image(&self, _image: &ImageWithDetails) -> Result<(), String> {
            todo!()
        }

        async fn create_image(&self, _docker_dir: &Path, _image: &Reference<'_>) -> Result<(), String> {
            todo!()
        }

        async fn create_container(&self, image: &Reference<'_>) -> Result<ContainerCreateInfo, String> {
            Ok(ContainerCreateInfo {
                id: image.to_string(),
                warnings: None,
            })
        }

        async fn force_delete_container(&self, _container_name: &str) -> Result<(), String> {
            Ok(())
        }

        async fn export_container_file_system(&self, _container_name: &str) -> Result<Vec<u8>, String> {
            let mut header = Header::new_gnu();
            let data: &[u8] = TEST_DATA.as_bytes();

            header.set_size(data.len() as u64);
            header.set_mode(0o777);
            header.set_cksum();

            let mut archive = Builder::new(Vec::new());
            archive
                .append_data(&mut header, TEST_FS_FILE, data)
                .expect("Failed writing test data to archive.");

            Ok(archive.into_inner().expect("Failed finishing archive."))
        }
    }

    const TEST_DATA: &'static str = "Hello World";

    const TEST_FS_FILE: &'static str = "test-fs";

    #[tokio::test]
    async fn export_image_file_system_correct_pass() {
        let temp_dir = TempDir::new().expect("Failed creating temp dir");

        let client_image_reference = DockerReference::from_str("test").expect("Failed creating docker reference");
        let enclave_builder = EnclaveImageBuilder {
            client_image_reference: &client_image_reference,
            dir: &temp_dir,
            enclave_base_image: None,
        };

        enclave_builder
            .export_image_file_system(&TestDockerDaemon {}, temp_dir.path())
            .await
            .expect("Failed exporting image file system");

        let mut result_file = fs::OpenOptions::new()
            .read(true)
            .open(temp_dir.path().join(TEST_FS_FILE))
            .expect("Cannot open result file");

        let mut result = String::new();
        result_file.read_to_string(&mut result).expect("Failed reading result file");

        assert_eq!(result, TEST_DATA)
    }

    #[test]
    fn enclave_settings_ctor_should_produce_correct_env_vars_string() {
        let reference = DockerReference::from_str("test").unwrap();
        let details = ImageDetails {
            architecture: "".to_string(),
            author: "".to_string(),
            comment: "".to_string(),
            config: ContainerConfig {
                attach_stderr: false,
                attach_stdin: false,
                attach_stdout: false,
                cmd: None,
                domainname: "".to_string(),
                entrypoint: None,
                env: None,
                exposed_ports: None,
                hostname: "".to_string(),
                image: "".to_string(),
                labels: None,
                on_build: None,
                open_stdin: false,
                stdin_once: false,
                tty: false,
                user: "".to_string(),
                working_dir: "".to_string(),
            },
            created: DateTime::<Utc>::MAX_UTC,
            docker_version: "".to_string(),
            id: "".to_string(),
            os: "".to_string(),
            parent: "".to_string(),
            repo_tags: None,
            repo_digests: None,
            size: 0,
            virtual_size: 0,
        };

        let mut input_image = ImageWithDetails { reference, details };

        let mut converter_options = ConverterOptions {
            allow_cmdline_args: None,
            allow_docker_pull_failure: None,
            app: None,
            ca_certificates: vec![],
            certificates: vec![],
            debug: None,
            entry_point: vec![],
            entry_point_args: vec![],
            push_converted_image: None,
            env_vars: vec![],
            java_mode: None,
        };

        let mut test = |input_image_env_vars: Option<Vec<String>>,
                        converter_request_env_vars: Vec<String>,
                        reference: Vec<String>|
         -> () {
            input_image.details.config.env = input_image_env_vars;
            converter_options.env_vars = converter_request_env_vars;

            let result = EnclaveSettings::new(&input_image, &converter_options);

            assert_eq!(result.env_vars, reference);
        };

        test(
            Some(vec![
                "A=A_VALUE".to_string(),
                "B=B_VALUE".to_string(),
                "C=C_VALUE".to_string(),
            ]),
            vec!["A=A_VALUE_NEW".to_string(), "C=C_VALUE_NEW".to_string()],
            vec![
                "A=A_VALUE".to_string(),
                "B=B_VALUE".to_string(),
                "C=C_VALUE".to_string(),
                "A=A_VALUE_NEW".to_string(),
                "C=C_VALUE_NEW".to_string(),
            ],
        );

        test(
            None,
            vec!["A=A_VALUE_NEW".to_string(), "C=C_VALUE_NEW".to_string()],
            vec!["A=A_VALUE_NEW".to_string(), "C=C_VALUE_NEW".to_string()],
        );

        test(
            Some(vec![
                "A=A_VALUE".to_string(),
                "B=B_VALUE".to_string(),
                "C=C_VALUE".to_string(),
            ]),
            vec![],
            vec!["A=A_VALUE".to_string(), "B=B_VALUE".to_string(), "C=C_VALUE".to_string()],
        );
    }
}
