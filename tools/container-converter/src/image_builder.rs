use tempfile::TempDir;
use log::{info};
use docker_image_reference::{Reference as DockerReference};

use crate::file::{DockerCopyArgs, UnixFile, Resource};
use crate::image::{DockerUtil, create_nitro_image, PCRList, ImageWithDetails};
use crate::{file, ConverterError, ConverterErrorKind};
use crate::Result;
use api_model::NitroEnclavesConversionRequestOptions;
use api_model::shared::{EnclaveSettings};

use std::fs;
use std::io::{Write};
use std::path::{PathBuf, Path};
use std::sync::mpsc::Sender;

pub struct EnclaveImageBuilder<'a> {
    pub client_image: DockerReference<'a>,

    pub dir: &'a TempDir,
}

pub struct EnclaveBuilderResult {
    pub nitro_file: String,

    pub pcr_list: PCRList,
}

impl<'a> EnclaveImageBuilder<'a> {

    pub async fn create_image(&self, docker_util : &'a DockerUtil, enclave_settings : EnclaveSettings, images_to_clean_snd: Sender<String>) -> Result<EnclaveBuilderResult> {
        self.create_requisites(enclave_settings).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        info!("Enclave prerequisites have been created!");

        let enclave_image_str = self.enclave_image();
        let enclave_image_reference = DockerReference::from_str(&enclave_image_str)
            .map_err(|message| ConverterError {
                message: format!("Failed to create enclave image reference. {:?}", message),
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        // This image is made temporary because it is only used by nitro-cli to create an `.eif` file.
        // After nitro-cli finishes we can safely reclaim it.
        let _ = create_image(
            docker_util,
            &enclave_image_reference,
            self.dir.path(),
            ConverterErrorKind::EnclaveImageCreation)
            .await
            .map(|e| e.make_temporary(images_to_clean_snd))?;

        let nitro_file = enclave_image_reference.name().to_string() + ".eif";
        let nitro_image_path = &self.dir.path().join(&nitro_file);

        let nitro_measurements = create_nitro_image(&enclave_image_reference, &nitro_image_path)?;

        info!("Nitro image has been created!");

        Ok(EnclaveBuilderResult {
            nitro_file,
            pcr_list: nitro_measurements.pcr_list,
        })
    }

    fn enclave_image(&self) -> String {
        let new_tag = self.client_image.tag()
            .map(|e| e.to_string() + "-enclave")
            .unwrap_or("enclave".to_string());

        self.client_image.name().to_string() + ":" + &new_tag
    }

    fn resources(&self) -> Vec<file::Resource> {
        vec![
            file::Resource {
                name: "start-enclave.sh".to_string(),
                data: include_bytes!("resources/enclave/start-enclave.sh").to_vec(),
                is_executable: true
            },
            file::Resource {
                name: "enclave".to_string(),
                data: include_bytes!("resources/enclave/enclave").to_vec(),
                is_executable: true
            },
        ]
    }

    fn requisites(&self) -> Vec<String> {
        vec![
            "start-enclave.sh".to_string(),
            "enclave".to_string(),
        ]
    }

    fn startup_path(&self) -> PathBuf {
        self.dir.path().join("start-enclave.sh")
    }

    fn create_requisites(&self, enclave_settings : EnclaveSettings) -> std::result::Result<(), String> {
        let mut docker_file = file::create_docker_file(self.dir.path())?;

        let requisites = {
            let mut result = self.requisites();

            result.push("enclave-settings.json".to_string());

            result
        };
        let copy = DockerCopyArgs::copy_to_home(requisites);

        file::populate_docker_file(&mut docker_file,
                                   &self.client_image.to_string(),
                                   &copy,
                                   "./start-enclave.sh",
                                   &rust_log_env_var())?;

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
                is_executable: false
            });

            result
        };

        file::create_resources(&resources, self.dir.path())?;

        self.create_enclave_startup_script()?;

        if cfg!(debug_assertions) {
            file::log_file(&self.startup_path())?;
        }

        Ok(())
    }

    fn create_enclave_startup_script(&self) -> std::result::Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&self.dir.path().join("start-enclave.sh"))
            .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

        file.set_execute().map_err(|err| format!("Cannot change permissions for a file {:?}", err))?;

        Ok(())
    }
}

pub struct ParentImageBuilder<'a> {
    pub output_image: DockerReference<'a>,

    pub parent_image: String,

    pub nitro_file: String,

    pub dir: &'a TempDir,

    pub start_options: NitroEnclavesConversionRequestOptions
}

impl<'a> ParentImageBuilder<'a> {

    const DEFAULT_CPU_COUNT : u8 = 2;

    const DEFAULT_MEMORY_SIZE : u64 = 2048;

    fn startup_path(&self) -> PathBuf {
        self.dir.path().join("start-parent.sh")
    }

    pub async fn create_image(&self, docker_util : &DockerUtil) -> Result<ImageWithDetails> {
        self.create_requisites()
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation
            })?;
        info!("Parent prerequisites have been created!");

        let result = create_image(
            docker_util,
            &self.output_image,
            self.dir.path(),
            ConverterErrorKind::ParentImageCreation).await?;

        info!("Parent image has been created!");

        Ok(result)
    }

    fn create_requisites(&self) -> std::result::Result<(), String> {
        let all_requisites = {
            let mut result = self.requisites();
            result.push(self.nitro_file.clone());
            result
        };

        let mut docker_file = file::create_docker_file(self.dir.path())?;

        let copy = DockerCopyArgs::copy_to_home(all_requisites);

        file::populate_docker_file(&mut docker_file,
                                   &self.parent_image,
                                   &copy,
                                   "./start-parent.sh",
                                   &rust_log_env_var())?;

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

    fn create_parent_startup_script(&self) -> std::result::Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(self.startup_path())
            .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

        let start_enclave_command = self.start_enclave_command();

        file.write_all(start_enclave_command.as_bytes())
            .map_err(|err| format!("Failed to write to file {:?}", err))?;

        if cfg!(debug_assertions) {
            file.write_all(ParentImageBuilder::connect_to_enclave_command().as_bytes())
                .map_err(|err| format!("Failed to write to file {:?}", err))?;
        }

        file.set_execute().map_err(|err| format!("Cannot change permissions for a file {:?}", err))?;

        Ok(())
    }

    fn start_enclave_command(&self) -> String {
        let sanitized_nitro_file = format!("'{}'", self.nitro_file);

        let cpu_count = self.start_options
            .cpu_count.
            unwrap_or(ParentImageBuilder::DEFAULT_CPU_COUNT);

        let memory_size = self.start_options
            .mem_size
            .as_ref()
            .map(|e| e.to_mb())
            .unwrap_or(ParentImageBuilder::DEFAULT_MEMORY_SIZE);

        // We start the parent side of the vsock proxy before running the enclave because we want it running
        // first. The nitro-cli run-enclave command exits after starting the enclave, so we foreground proxy
        // parent process so our container will stay running as long as the parent process stays running.

        let debug_mode = if cfg!(debug_assertions) { "--debug-mode" } else { "" };

        format!(
            "\n\
             # Parent startup code \n\
             ./parent --vsock-port 5006 & \n\
             nitro-cli run-enclave --eif-path {} --cpu-count {} --memory {} {}\n\
             fg\n",
            sanitized_nitro_file,
            cpu_count,
            memory_size,
            debug_mode)
    }

    fn connect_to_enclave_command() -> String {
        "\n\
         cat /var/log/nitro_enclaves/* \n\
         ID=$(nitro-cli describe-enclaves | jq '.[0] | .EnclaveID') \n\
         ID=\"${ID%\\\"}\" \n\
         ID=\"${ID#\\\"}\" \n\
         nitro-cli console --enclave-id $ID \n".to_string()
    }

    fn resources(&self) -> Vec<file::Resource> {
        vec![
            file::Resource {
                name: "start-parent.sh".to_string(),
                data: include_bytes!("resources/parent/start-parent.sh").to_vec(),
                is_executable: true
            },
            file::Resource {
                name: "parent".to_string(),
                data: include_bytes!("resources/parent/parent").to_vec(),
                is_executable: true
            }
        ]
    }

    fn requisites(&self) -> Vec<String> {
        vec![
            "start-parent.sh".to_string(),
            "parent".to_string()
        ]
    }
}

async fn create_image(docker_util : &DockerUtil, image : &DockerReference<'_>, dir : &Path, kind : ConverterErrorKind) -> Result<ImageWithDetails> {
    docker_util.create_image(dir, image)
        .await
        .map_err(|message| ConverterError {
            message,
            kind
        })?;

    docker_util.get_image(image)
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::ImageGet
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