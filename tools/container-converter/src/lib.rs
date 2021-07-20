pub mod image;
pub mod file;

use file::UnixFile;
use image::{
    DockerUtil,
    create_nitro_image
};
use tempfile::TempDir;
use crate::file::DockerCopyArgs;

use log::debug;

use std::fs;
use std::io::Write;

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

        debug!("Creating enclave prerequisites!");
        self.create_requisites()?;

        debug!("Creating enclave image using buildkit!");
        docker_util.create_image(self.dir.path(), &enclave_image_name)?;

        debug!("Creating nitro image!");
        create_nitro_image(&enclave_image_name, &nitro_image_path)?;
        debug!("Nitro image has been created!");

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
            }
        ]
    }

    fn requisites(&self) -> Vec<String> {
        vec![
            "start-enclave.sh".to_string(),
            "vsock-proxy".to_string()
        ]
    }

    fn create_requisites(&self) -> Result<(), String> {
        let mut docker_file = file::create_docker_file(self.dir.path())?;

        let copy = DockerCopyArgs::copy_to_home(self.requisites());

        file::populate_docker_file(&mut docker_file, &self.client_image, &copy, "./start-enclave.sh")?;

        file::create_resources(&self.resources(), self.dir.path())?;

        self.create_enclave_startup_script()?;

        Ok(())
    }

    fn create_enclave_startup_script(&self) -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&self.dir.path().join("start-enclave.sh"))
            .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

        // todo: sanitize the user cmd before putting it into startup script.
        // Escape chars like: ' ” \ or ;.
        let cmd = self.client_cmd.join(" ");

        file.write_all(cmd.as_bytes()).map_err(|err| format!("Failed to write to file {:?}", err))?;

        file.set_execute().map_err(|err| format!("Cannot change permissions for a file {:?}", err))?;

        Ok(())
    }
}

pub struct ParentImageBuilder<'a> {
    pub client_image : String,

    pub parent_image : String,

    pub nitro_file : String,

    pub dir : &'a TempDir
}

impl<'a> ParentImageBuilder<'a> {

    pub fn create_image(&self, docker_util : &DockerUtil) -> Result<(), String> {
        debug!("Creating parent prerequisites!");
        self.create_requisites()?;

        debug!("Creating parent image!");
        let result_image_name = self.client_image.clone() + "-parent";

        docker_util.create_image(self.dir.path(), &result_image_name)?;
        debug!("Parent image has been created!");

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

        file::populate_docker_file(&mut docker_file, &self.parent_image, &copy, "./start-parent.sh")?;

        file::create_resources(&self.resources(), self.dir.path())?;

        self.create_parent_startup_script()?;

        Ok(())
    }

    fn create_parent_startup_script(&self) -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(self.dir.path().join("start-parent.sh"))
            .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

        let cmd = format!(
            "./vsock-proxy proxy --remote-port 5000 --vsock-port 5006 & \n\
             nitro-cli run-enclave --eif-path {} --enclave-cid 4 --cpu-count 2 --memory 1124 --debug-mode \n",
            self.nitro_file);

        file.write_all(cmd.as_bytes()).map_err(|err| format!("Failed to write to file {:?}", err))?;

        let debug = true;
        if debug {
            let cmd = "cat /var/log/nitro_enclaves/* \n\
             ID=$(nitro-cli describe-enclaves | jq '.[0] | .EnclaveID') \n\
             ID=\"${ID%\\\"}\" \n\
             ID=\"${ID#\\\"}\" \n\
             nitro-cli console --enclave-id $ID \n";

            file.write_all(cmd.as_bytes()).map_err(|err| format!("Failed to write to file {:?}", err))?;
        }

        file.set_execute().map_err(|err| format!("Cannot change permissions for a file {:?}", err))?;

        Ok(())
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
            }
        ]
    }

    fn requisites(&self) -> Vec<String> {
        vec![
            "allocator.yaml".to_string(),
            "start-parent.sh".to_string(),
            "vsock-proxy".to_string()
        ]
    }
}

pub fn global_resources() -> Vec<file::Resource> {
    vec![
        file::Resource {
            name: "vsock-proxy".to_string(),
            data: include_bytes!("resources/vsock-proxy").to_vec(),
        }
    ]
}
