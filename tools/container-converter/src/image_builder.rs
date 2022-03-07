use docker_image_reference::Reference as DockerReference;
use log::info;
use tempfile::TempDir;

use crate::file::{DockerCopyArgs, Resource, UnixFile};
use crate::image::{create_nitro_image, DockerUtil, ImageWithDetails, PCRList};
use crate::Result;
use crate::{file, ConverterError, ConverterErrorKind};
use api_model::shared::EnclaveSettings;
use api_model::NitroEnclavesConversionRequestOptions;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

pub struct EnclaveImageBuilder<'a> {
    pub client_image: DockerReference<'a>,

    pub dir: &'a TempDir,
}

pub struct EnclaveBuilderResult {
    pub pcr_list: PCRList,
}

const INSTALLATION_DIR: &'static str = "/opt/fortanix/enclave-os";

impl<'a> EnclaveImageBuilder<'a> {
    pub const ENCLAVE_FILE_NAME: &'static str = "enclave.eif";

    const DEFAULT_ENCLAVE_SETTINGS_FILE: &'static str = "enclave-settings.json";

    pub async fn create_image(
        &self,
        docker_util: &'a DockerUtil,
        enclave_settings: EnclaveSettings,
        images_to_clean_snd: Sender<String>,
    ) -> Result<EnclaveBuilderResult> {
        self.create_requisites(enclave_settings).map_err(|message| ConverterError {
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
        .map(|e| e.make_temporary(images_to_clean_snd))?;

        let nitro_image_path = &self.dir.path().join(EnclaveImageBuilder::ENCLAVE_FILE_NAME);

        let nitro_measurements = create_nitro_image(&enclave_image_reference, &nitro_image_path)?;

        info!("Nitro image has been created!");

        Ok(EnclaveBuilderResult {
            pcr_list: nitro_measurements.pcr_list,
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

    fn resources(&self) -> Vec<file::Resource> {
        vec![file::Resource {
            name: "enclave".to_string(),
            data: include_bytes!("resources/enclave/enclave").to_vec(),
            is_executable: true,
        }]
    }

    fn requisites(&self) -> Vec<String> {
        vec!["enclave".to_string(), "enclave-settings.json".to_string()]
    }

    fn create_requisites(&self, enclave_settings: EnclaveSettings) -> std::result::Result<(), String> {
        let mut docker_file = file::create_docker_file(self.dir.path())?;

        self.populate_docker_file(&mut docker_file, &enclave_settings)?;

        if cfg!(debug_assertions) {
            file::log_docker_file(self.dir.path())?;
        }

        let resources = {
            let mut result = self.resources();

            let data = serde_json::to_vec(&enclave_settings)
                .map_err(|err| format!("Failed serializing enclave settings file. {:?}", err))?;

            result.push(Resource {
                name: "enclave-settings.json".to_string(),
                data,
                is_executable: false,
            });

            result
        };

        file::create_resources(&resources, self.dir.path())?;

        Ok(())
    }

    fn populate_docker_file(&self, file: &mut fs::File, enclave_settings: &EnclaveSettings) -> std::result::Result<(), String> {
        let install_dir_path = Path::new(INSTALLATION_DIR);

        let copy = DockerCopyArgs {
            items: self.requisites(),
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

            format!(
                "{} {} --vsock-port 5006 --settings-path {}",
                switch_user_cmd,
                enclave_bin.display(),
                enclave_settings_file.display()
            )
        };

        file::populate_docker_file(
            file,
            &self.client_image.to_string(),
            &copy,
            &rust_log_env_var(),
            &run_enclave_cmd,
        )
    }
}

pub struct ParentImageBuilder<'a> {
    pub output_image: DockerReference<'a>,

    pub parent_image: String,

    pub dir: &'a TempDir,

    pub start_options: NitroEnclavesConversionRequestOptions,
}

impl<'a> ParentImageBuilder<'a> {
    const DEFAULT_CPU_COUNT: u8 = 2;

    const DEFAULT_MEMORY_SIZE: u64 = 2048;

    fn startup_path(&self) -> PathBuf {
        self.dir.path().join("start-parent.sh")
    }

    pub async fn create_image(&self, docker_util: &DockerUtil) -> Result<ImageWithDetails> {
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

        file::create_resources(&self.resources(), self.dir.path())?;

        self.create_parent_startup_script()?;

        if cfg!(debug_assertions) {
            file::log_file(&self.startup_path())?;
        }

        Ok(())
    }

    fn populate_docker_file(&self, file: &mut fs::File) -> std::result::Result<(), String> {
        let copy = DockerCopyArgs {
            items: self.requisites(),
            destination: INSTALLATION_DIR.to_string() + "/",
        };

        let run_parent_cmd = Path::new(INSTALLATION_DIR).join("start-parent.sh").display().to_string();

        let env_vars = rust_log_env_var()
            + " "
            + &(self.cpu_count_env_var())
            + " "
            + &(self.mem_size_env_var())
            + " "
            + &(self.eos_debug_env_var());

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

        // We start the parent side of the vsock proxy before running the enclave because we want it running
        // first. The nitro-cli run-enclave command exits after starting the enclave, so we foreground proxy
        // parent process so our container will stay running as long as the parent process stays running.
        format!(
            "\n\
             # Parent startup code \n\
             {} --vsock-port 5006 & \n\
             dbg_cmd=\"{}\" \n\
             cmd=\"{}\" \n\
             if [ -n \"$ENCLAVEOS_DEBUG\" ] ; then eval \"$dbg_cmd\" ; else eval \"$cmd\" ; fi; \n\
             fg \n",
            parent_bin.display(),
            dbg_cmd,
            cmd
        )
    }

    fn resources(&self) -> Vec<file::Resource> {
        vec![
            file::Resource {
                name: "start-parent.sh".to_string(),
                data: include_bytes!("resources/parent/start-parent.sh").to_vec(),
                is_executable: true,
            },
            file::Resource {
                name: "parent".to_string(),
                data: include_bytes!("resources/parent/parent").to_vec(),
                is_executable: true,
            },
        ]
    }

    fn requisites(&self) -> Vec<String> {
        vec![
            "start-parent.sh".to_string(),
            "parent".to_string(),
            EnclaveImageBuilder::ENCLAVE_FILE_NAME.to_string(),
        ]
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

async fn create_image(
    docker_util: &DockerUtil,
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

fn rust_log_env_var() -> String {
    format!("RUST_LOG={}", {
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "info"
        }
    })
}
