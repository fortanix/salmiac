pub mod image;
pub mod file;

use file::UnixFile;
use image::{
    DockerUtil,
    create_nitro_image
};
use tempfile::TempDir;
use crate::file::{
    DockerCopyArgs
};

use log::{
    info
};

use std::fs;
use std::io::{Write};
use std::path::{PathBuf};

pub struct EnclaveImageBuilder<'a> {
    pub client_image : String,

    pub client_cmd : Vec<String>,

    pub dir : &'a TempDir
}

impl<'a> EnclaveImageBuilder<'a> {

    pub fn nitro_image_name(&self) -> String {
        self.enclave_image_name() + ".eif"
    }

    pub fn create_image(&self, docker_util : &DockerUtil) -> Result<(), String> {
        let enclave_image_name = self.enclave_image_name();
        let nitro_image_path = &self.dir.path().join(&self.nitro_image_name());

        self.create_requisites()?;
        info!("Enclave prerequisites have been created!");

        docker_util.create_image(self.dir.path(), &enclave_image_name)?;

        create_nitro_image(&enclave_image_name, &nitro_image_path)?;
        info!("Nitro image has been created!");

        Ok(())
    }

    fn enclave_image_name(&self) -> String {
        self.client_image.clone() + "-enclave"
    }

   /* fn enclave_image_tar_path(&self) -> Path {
        let enclave_image_tar = self.enclave_image_name() + ".tar";

        self.dir.path().join(&enclave_image_tar).as_path()
    }*/

    fn resources(&self) -> Vec<file::Resource> {
        vec![
            file::Resource {
                name: "start-enclave.sh".to_string(),
                data: include_bytes!("resources/enclave/start-enclave.sh").to_vec(),
            },
            file::Resource {
                name: "enclave".to_string(),
                data: include_bytes!("resources/enclave/enclave").to_vec(),
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

    fn create_requisites(&self) -> Result<(), String> {

        let mut docker_file = file::create_docker_file(self.dir.path())?;

        let copy = DockerCopyArgs::copy_to_home(self.requisites());

        file::populate_docker_file(&mut docker_file,
                                   &self.client_image,
                                   &copy,
                                   "./start-enclave.sh",
                                   &rust_log_env_var())?;

        if cfg!(debug_assertions) {
            file::log_docker_file(self.dir.path())?;
        }

        file::create_resources(&self.resources(), self.dir.path())?;

        self.create_enclave_startup_script()?;

        if cfg!(debug_assertions) {
            file::log_file(&self.startup_path())?;
        }

        Ok(())
    }

    fn create_enclave_startup_script(&self) -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&self.dir.path().join("start-enclave.sh"))
            .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

        if cfg!(debug_assertions) {
            file.write_all(EnclaveImageBuilder::debug_networking_command().as_bytes()).map_err(|err| format!("Failed to write to file {:?}", err))?;
        }

        // todo: sanitize the user cmd before putting it into startup script.
        // Escape chars like: ' ” \ or ;.
        let cmd = "\n".to_string() + &self.client_cmd.join(" ");

        file.write_all(cmd.as_bytes()).map_err(|err| format!("Failed to write to file {:?}", err))?;

        file.set_execute().map_err(|err| format!("Cannot change permissions for a file {:?}", err))?;

        Ok(())
    }

    fn debug_networking_command() -> String {
        "\n\
        # Debug code. \n\
        # Dumps networking info to make sure that enclave is setup correctly \n\
        sleep 30 \n\
        echo \"Devices start\" \n\
        ip a \n\
        echo \"Devices end\" \n\
        echo \"Routes start\" \n\
        ip r \n\
        echo \"Routes end\" \n\
        echo \"ARP start\" \n\
        ip neigh \n\
        echo \"ARP end\" \n".to_string()
    }
}

pub struct ParentImageBuilder<'a> {
    pub output_image : String,

    pub parent_image : String,

    pub nitro_file : String,

    pub dir : &'a TempDir
}

impl<'a> ParentImageBuilder<'a> {

    fn startup_path(&self) -> PathBuf {
        self.dir.path().join("start-parent.sh")
    }

    pub fn create_image(&self, docker_util : &DockerUtil) -> Result<(), String> {
        self.create_requisites()?;
        info!("Parent prerequisites have been created!");

        docker_util.create_image(self.dir.path(), &self.output_image)?;
        info!("Parent image has been created!");

        Ok(())
    }

    fn create_requisites(&self) -> Result<(), String> {
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

    fn create_parent_startup_script(&self) -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(self.startup_path())
            .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

        file.write_all(self.start_enclave_command().as_bytes())
            .map_err(|err| format!("Failed to write to file {:?}", err))?;

        file.write_all(ParentImageBuilder::connect_to_enclave_command().as_bytes())
            .map_err(|err| format!("Failed to write to file {:?}", err))?;

        file.set_execute().map_err(|err| format!("Cannot change permissions for a file {:?}", err))?;

        Ok(())
    }

    fn start_enclave_command(&self) -> String {
        let sanitized_nitro_file = format!("'{}'", self.nitro_file);

        format!(
            "\n\
                ./parent --vsock-port 5006 & \n\
                nitro-cli run-enclave --eif-path {} --cpu-count 2 --memory 2200 --debug-mode \n",
            sanitized_nitro_file)
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
            },
            file::Resource {
                name: "allocator.yaml".to_string(),
                data: include_bytes!("resources/parent/allocator.yaml").to_vec(),
            },
            file::Resource {
                name: "parent".to_string(),
                data: include_bytes!("resources/parent/parent").to_vec(),
            }
        ]
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
