use tempfile::TempDir;
use log::{info};

use crate::file::{DockerCopyArgs, UnixFile, Resource};
use crate::image::{DockerUtil, create_nitro_image, PCRList};
use crate::{file, ConverterError, ConverterErrorKind};
use crate::Result;
use api_model::NitroEnclavesConversionRequestOptions;
use api_model::CertificateConfig;
use api_model::shared::EnclaveSettings;

use std::fs;
use std::io::{Write};
use std::path::{PathBuf};
use std::env;

pub struct EnclaveImageBuilder<'a> {
    pub client_image: String,

    pub client_cmd: Vec<String>,

    pub dir: &'a TempDir,

    pub certificate_settings: CertificateConfig
}

pub struct EnclaveBuilderResult {
    pub nitro_file: String,

    pub pcr_list: PCRList
}

impl<'a> EnclaveImageBuilder<'a> {

    pub async fn create_image(&self, docker_util : &DockerUtil) -> Result<EnclaveBuilderResult> {
        self.create_requisites().map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        info!("Enclave prerequisites have been created!");

        let enclave_image_name = self.enclave_image_name();
        docker_util.create_image(self.dir.path(), &enclave_image_name)
            .await
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::EnclaveImageCreation
            })?;

        let nitro_file = enclave_image_name.clone() + ".eif";
        let nitro_image_path = &self.dir.path().join(&nitro_file);

        let nitro_measurements = create_nitro_image(&enclave_image_name, &nitro_image_path)?;

        info!("Nitro image has been created!");

        Ok(EnclaveBuilderResult {
            nitro_file,
            pcr_list: nitro_measurements.measurements
        })
    }

    fn enclave_image_name(&self) -> String {
        self.client_image.clone().replace("/", "-") + "-enclave"
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

    fn create_requisites(&self) -> std::result::Result<(), String> {

        let mut docker_file = file::create_docker_file(self.dir.path())?;

        let requisites = {
            let mut result = self.requisites();

            result.push("enclave-settings.json".to_string());

            result
        };
        let copy = DockerCopyArgs::copy_to_home(requisites);

        file::populate_docker_file(&mut docker_file,
                                   &self.client_image,
                                   &copy,
                                   "./start-enclave.sh",
                                   &rust_log_env_var())?;

        if cfg!(debug_assertions) {
            file::log_docker_file(self.dir.path())?;
        }

        let resources = {
            let mut result = self.resources();

            let enclave_settings = self.create_enclave_settings();
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

    fn create_enclave_settings(&self) -> EnclaveSettings {
        // In docker CMD is present in the form of /bin/sh -c <client program> <client arguments>,
        // because of that we extract '/bin/sh` as a program that the enclave will run
        // and everything else becomes an argument list
        let client_cmd = self.client_cmd[0].clone();
        let client_cmd_args = self.client_cmd[1..].to_vec();

        EnclaveSettings {
            client_cmd,
            client_cmd_args,
            certificate_config: self.certificate_settings.clone()
        }
    }
}

pub struct ParentImageBuilder<'a> {
    pub output_image: String,

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

    pub async fn create_image(&self, docker_util : &DockerUtil) -> Result<()> {
        self.create_requisites()
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation
            })?;
        info!("Parent prerequisites have been created!");

        docker_util.create_image(self.dir.path(), &self.output_image)
            .await
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::ParentImageCreation
            })?;
        info!("Parent image has been created!");

        Ok(())
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

        let allocator_settings = if let Ok(allocator_settings_path) = env::var("NITRO_ALLOCATOR") {
            let data = fs::read(&allocator_settings_path)
                .map_err(|err| format!("Failed reading allocator settings from {}. {:?}", allocator_settings_path, err))?;

            file::Resource {
                name: "allocator.yaml".to_string(),
                data,
                is_executable: false,
            }
        } else {
            ParentImageBuilder::default_allocator_settings()
        };

        let resources = {
            let mut result = self.resources();
            result.push(allocator_settings);
            result
        };

        file::create_resources(&resources, self.dir.path())?;

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
            .map(|e| e.to_inner())
            .unwrap_or(ParentImageBuilder::DEFAULT_MEMORY_SIZE);

        let result = format!(
            "\n\
             ./parent --vsock-port 5006 & \n\
             nitro-cli run-enclave --eif-path {} --cpu-count {} --memory {}",
            sanitized_nitro_file,
            cpu_count,
            memory_size);

        if cfg!(debug_assertions) {
            result + " --debug-mode  \n"
        } else {
            result + " \n"
        }
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

    fn default_allocator_settings() -> file::Resource {
        file::Resource {
            name: "allocator.yaml".to_string(),
            data: include_bytes!("resources/parent/allocator.yaml").to_vec(),
            is_executable: false
        }
    }

    fn requisites(&self) -> Vec<String> {
        vec![
            "allocator.yaml".to_string(),
            "start-parent.sh".to_string(),
            "parent".to_string()
        ]
    }
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