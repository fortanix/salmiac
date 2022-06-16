use docker_image_reference::Reference as DockerReference;
use log::info;
use tempfile::TempDir;

use crate::file::{DockerCopyArgs, Resource, UnixFile};
use crate::image::{create_nitro_image, process_output, DockerUtil, ImageWithDetails, PCRList};
use crate::{file, ConverterError, ConverterErrorKind};
use crate::{ImageKind, ImageToClean, Result};
use api_model::shared::EnclaveSettings;
use api_model::NitroEnclavesConversionRequestOptions;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::mpsc::Sender;
use tar::Archive;

pub struct EnclaveImageBuilder<'a> {
    pub client_image: DockerReference<'a>,

    pub dir: &'a TempDir,

    pub enclave_base_image: Option<String>,
}

pub struct EnclaveBuilderResult {
    pub pcr_list: PCRList,

    pub block_file_present: bool
}

const INSTALLATION_DIR: &'static str = "/opt/fortanix/enclave-os";

impl<'a> EnclaveImageBuilder<'a> {
    pub const ENCLAVE_FILE_NAME: &'static str = "enclave.eif";

    const DEFAULT_ENCLAVE_SETTINGS_FILE: &'static str = "enclave-settings.json";

    const BLOCK_FILE_SCRIPT_NAME: &'static str = "create-block-file.sh";

    const BLOCK_FILE_INPUT_DIR: &'static str = "enclave-fs";

    const BLOCK_FILE_MOUNT_DIR: &'static str = "block-file-mount";

    pub const BLOCK_FILE_OUT: &'static str = "Blockfile.ext4";

    pub async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        enclave_settings: EnclaveSettings,
        env_vars: &Vec<String>,
        images_to_clean_snd: Sender<ImageToClean>
    ) -> Result<EnclaveBuilderResult> {
        self.create_requisites(enclave_settings, env_vars).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        info!("Enclave prerequisites have been created!");

        let enclave_image_str = self.enclave_image();
        let enclave_image_reference = DockerReference::from_str(&enclave_image_str).map_err(|message| ConverterError {
            message: format!("Failed to create enclave image reference. {:?}", message),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        // This image is made temporary because it is only used by nitro-cli to create an `.eif` file.
        // After nitro-cli finishes we can safely reclaim it.
        let _ = create_image(
            docker_util,
            &enclave_image_reference,
            self.dir.path(),
            ConverterErrorKind::EnclaveImageCreation,
        )
        .await
        .map(|e| e.make_temporary(ImageKind::Intermediate, images_to_clean_snd))?;

        self.create_block_file(docker_util).await?;
        info!("Block file has been created!");

        let block_file_present = if self.enclave_base_image.is_some() {
            self.create_block_file(docker_util).await?;
            info!("Block file has been created!");

            true
        } else {
            false
        };

        let nitro_image_path = &self.dir.path().join(EnclaveImageBuilder::ENCLAVE_FILE_NAME);

        let nitro_measurements = create_nitro_image(&enclave_image_reference, &nitro_image_path)?;

        info!("Nitro image has been created!");

        Ok(EnclaveBuilderResult {
            pcr_list: nitro_measurements.pcr_list,
            block_file_present
        })
    }

    async fn create_block_file(&self, docker_util: &dyn DockerUtil) -> Result<()> {
        let (block_file_input_root, block_file_mount_root) = self.create_block_file_dirs()?;
        let block_file_input_dir = block_file_input_root.path().join(EnclaveImageBuilder::BLOCK_FILE_INPUT_DIR);
        let block_file_mount_dir = block_file_mount_root.path().join(EnclaveImageBuilder::BLOCK_FILE_MOUNT_DIR);

        fs::create_dir(&block_file_input_dir)
            .map_err(|err| ConverterError {
                message: format!("Failed creating dir {}. {:?}", block_file_input_dir.display(), err),
                kind: ConverterErrorKind::BlockFileCreation,
            })?;

        fs::create_dir(&block_file_mount_dir)
            .map_err(|err| ConverterError {
                message: format!("Failed creating dir {}. {:?}", block_file_mount_dir.display(), err),
                kind: ConverterErrorKind::BlockFileCreation,
            })?;

        self.export_image_file_system(docker_util, &block_file_input_dir)
            .await?;

        let mut block_file_process = self.block_file_process(&block_file_input_dir, &block_file_mount_dir);

        let result = block_file_process.output().map_err(|err| ConverterError {
            message: format!("Failed creating block file. {:?}", err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        let _ = process_output(result, "create-block-file").map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        Ok(())
    }

    fn block_file_process(&self, input_dir: &Path, mount_dir: &Path) -> Command {
        let path_args = [
            input_dir,
            mount_dir,
            &self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_OUT),
        ];
        let block_file_script_path = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_SCRIPT_NAME);

        let mut result = process::Command::new(block_file_script_path);

        result.args(&path_args);
        result.arg("true");

        result
    }

    fn create_block_file_dirs(&self) -> Result<(TempDir, TempDir)> {
        fn temp_dir(in_dir: &Path) -> Result<TempDir> {
            tempfile::Builder::new()
                .tempdir_in(in_dir)
                .map_err(|err| ConverterError {
                    message: format!("Failed creating temp dir in {} for block file process. {:?}", in_dir.display(), err),
                    kind: ConverterErrorKind::RequisitesCreation,
                })
        }

        let input_dir = temp_dir(self.dir.path())?;
        let mount_dir = temp_dir(self.dir.path())?;

        Ok((input_dir, mount_dir))
    }

    async fn export_image_file_system(&self, docker_util: &dyn DockerUtil, out_dir: &Path) -> Result<()> {
        let client_file_system = docker_util
            .export_image_file_system(&self.client_image)
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
            .client_image
            .tag()
            .map(|e| e.to_string() + "-enclave")
            .unwrap_or("enclave".to_string());

        self.client_image.name().to_string() + ":" + &new_tag
    }

    const IMAGE_BUILD_DEPENDENCIES: &'static [Resource<'static>] = &[
        Resource {
            name: "enclave",
            data: include_bytes!("resources/enclave/enclave"),
            is_executable: true,
        },
        Resource {
            name: EnclaveImageBuilder::BLOCK_FILE_SCRIPT_NAME,
            data: include_bytes!("resources/fs/configure"),
            is_executable: true,
        }
    ];

    const IMAGE_COPY_DEPENDENCIES: &'static [&'static str] = &["enclave", "enclave-settings.json"];

    fn create_requisites(&self, enclave_settings: EnclaveSettings, env_vars: &Vec<String>) -> std::result::Result<(), String> {
        let mut docker_file = file::create_docker_file(self.dir.path())?;

        self.populate_docker_file(&mut docker_file, &enclave_settings, env_vars)?;

        if cfg!(debug_assertions) {
            file::log_docker_file(self.dir.path())?;
        }

        let mut resources = EnclaveImageBuilder::IMAGE_BUILD_DEPENDENCIES.to_vec();

        let data = serde_json::to_vec(&enclave_settings)
            .map_err(|err| format!("Failed serializing enclave settings file. {:?}", err))?;

        resources.push(Resource {
            name: "enclave-settings.json",
            data: &data,
            is_executable: false,
        });

        file::create_resources(&resources, self.dir.path())?;

        Ok(())
    }

    fn populate_docker_file(&self, file: &mut fs::File, enclave_settings: &EnclaveSettings, env_vars: &Vec<String>) -> std::result::Result<(), String> {
        let install_dir_path = Path::new(INSTALLATION_DIR);

        let copy = DockerCopyArgs {
            items: EnclaveImageBuilder::IMAGE_COPY_DEPENDENCIES.to_vec(),
            destination: INSTALLATION_DIR.to_string() + "/",
        };

        let run_enclave_cmd = {
            let enclave_bin = install_dir_path.join("enclave");

            let enclave_settings_file = install_dir_path.join(EnclaveImageBuilder::DEFAULT_ENCLAVE_SETTINGS_FILE);

            let user_name = {
                if let Some(pos) = enclave_settings.user.find(":") {
                    &enclave_settings.user[..pos]
                } else {
                    &enclave_settings.user
                }
            };

            // Quick fix for: https://fortanix.atlassian.net/browse/SALM-94
            // Sets the home variable specifically for applications that require it to run
            let switch_user_cmd = if user_name != "" && user_name != "root" {
                format!("export HOME=/home/{};", user_name)
            } else {
                String::new()
            };

            let use_file_system_flag = if self.enclave_base_image.is_some() {
                "--use-file-system"
            } else {
                ""
            };

            format!(
                "{} {} --vsock-port 5006 --settings-path {} {}",
                switch_user_cmd,
                enclave_bin.display(),
                enclave_settings_file.display(),
                use_file_system_flag
            )
        };

        let client_image = &self.client_image.to_string();
        let from = match &self.enclave_base_image {
            Some(e) => { e }
            _ => { client_image }
        };

        let mut env = env_vars.clone();
        env.push(rust_log_env_var("enclave"));

        file::populate_docker_file(
            file,
            from,
            &copy,
            &env,
            &run_enclave_cmd,
        )
    }
}

pub struct ParentImageBuilder<'a> {
    pub output_image: DockerReference<'a>,

    pub parent_image: String,

    pub dir: &'a TempDir,

    pub start_options: NitroEnclavesConversionRequestOptions,

    pub block_file_present: bool
}

impl<'a> ParentImageBuilder<'a> {
    const DEFAULT_CPU_COUNT: u8 = 2;

    const DEFAULT_MEMORY_SIZE: u64 = 2048;

    fn startup_path(&self) -> PathBuf {
        self.dir.path().join("start-parent.sh")
    }

    pub async fn create_image(&self, docker_util: &dyn DockerUtil) -> Result<ImageWithDetails> {
        self.create_requisites().map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })?;
        info!("Parent prerequisites have been created!");

        let result = create_image(
            docker_util,
            &self.output_image,
            self.dir.path(),
            ConverterErrorKind::ParentImageCreation,
        )
        .await?;

        info!("Parent image has been created!");

        Ok(result)
    }

    fn create_requisites(&self) -> std::result::Result<(), String> {
        let mut docker_file = file::create_docker_file(self.dir.path())?;

        self.populate_docker_file(&mut docker_file)?;

        if cfg!(debug_assertions) {
            file::log_docker_file(self.dir.path())?;
        }

        file::create_resources(ParentImageBuilder::IMAGE_BUILD_DEPENDENCIES, self.dir.path())?;

        self.create_parent_startup_script()?;

        if cfg!(debug_assertions) {
            file::log_file(&self.startup_path())?;
        }

        Ok(())
    }

    fn populate_docker_file(&self, file: &mut fs::File) -> std::result::Result<(), String> {
        let mut items = ParentImageBuilder::IMAGE_COPY_DEPENDENCIES.to_vec();
        if self.block_file_present {
            items.push(EnclaveImageBuilder::BLOCK_FILE_OUT)
        }

        let copy = DockerCopyArgs {
            items,
            destination: INSTALLATION_DIR.to_string() + "/",
        };

        let run_parent_cmd = Path::new(INSTALLATION_DIR).join("start-parent.sh").display().to_string();

        let env_vars = vec![
            rust_log_env_var("parent"),
            self.cpu_count_env_var(),
            self.mem_size_env_var(),
            self.eos_debug_env_var()];

        file::populate_docker_file(file, &self.parent_image, &copy, &env_vars, &run_parent_cmd)
    }

    fn create_parent_startup_script(&self) -> std::result::Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(self.startup_path())
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
        let use_file_system_flag = if self.block_file_present {
            "--use-file-system"
        } else {
            ""
        };
        // We start the parent side of the vsock proxy before running the enclave because we want it running
        // first. The nitro-cli run-enclave command exits after starting the enclave, so we foreground proxy
        // parent process so our container will stay running as long as the parent process stays running.
        format!(
            "\n\
             # Parent startup code \n\
             {} --vsock-port 5006 {} & \n\
             dbg_cmd=\"{}\" \n\
             cmd=\"{}\" \n\
             if [ -n \"$ENCLAVEOS_DEBUG\" ] ; then eval \"$dbg_cmd\" ; else eval \"$cmd\" ; fi; \n\
             fg \n",
            parent_bin.display(),
            use_file_system_flag,
            dbg_cmd,
            cmd
        )
    }

    const IMAGE_BUILD_DEPENDENCIES: &'static [Resource<'static>] = &[
        file::Resource {
            name: "start-parent.sh",
            data: include_bytes!("resources/parent/start-parent.sh"),
            is_executable: true,
        },
        file::Resource {
            name: "parent",
            data: include_bytes!("resources/parent/parent"),
            is_executable: true,
        },
    ];

    const IMAGE_COPY_DEPENDENCIES: &'static [&'static str] = &[
        "start-parent.sh",
        "parent",
        EnclaveImageBuilder::ENCLAVE_FILE_NAME
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

async fn create_image(
    docker_util: &dyn DockerUtil,
    image: &DockerReference<'_>,
    dir: &Path,
    kind: ConverterErrorKind,
) -> Result<ImageWithDetails> {
    docker_util
        .create_image(dir, image)
        .await
        .map_err(|message| ConverterError { message, kind })?;

    docker_util.get_image(image).await.map_err(|message| ConverterError {
        message,
        kind: ConverterErrorKind::ImageGet,
    })
}

fn rust_log_env_var(project_name: &str) -> String {
    let log_level = if cfg!(debug_assertions) {
        "debug"
    } else {
        "info"
    };

    format!("RUST_LOG={}={}", project_name, log_level)
}

#[cfg(test)]
mod tests {
    use crate::image::{DockerUtil, ImageWithDetails};
    use crate::EnclaveImageBuilder;
    use async_trait::async_trait;
    use docker_image_reference::Reference;
    use docker_image_reference::Reference as DockerReference;
    use shiplift::container::ContainerCreateInfo;
    use std::fs;
    use std::io::Read;
    use std::path::Path;
    use tar::{Builder, Header};
    use tempfile::TempDir;

    struct TestDockerDaemon {}

    #[async_trait]
    impl DockerUtil for TestDockerDaemon {
        async fn get_image(&self, _image: &Reference<'_>) -> Result<ImageWithDetails, String> {
            todo!()
        }

        async fn load_image(&self, _tar_path: &str) -> Result<(), String> {
            todo!()
        }

        async fn push_image(&self, _image: &ImageWithDetails, _address: &Reference<'_>) -> Result<(), String> {
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

        let enclave_builder = EnclaveImageBuilder {
            client_image: DockerReference::from_str("test").expect("Failed creating docker reference"),
            dir: &temp_dir,
            enclave_base_image: None
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
}
