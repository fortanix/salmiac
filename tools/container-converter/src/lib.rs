pub mod image;
pub mod file;

use image::{
    DockerUtil,
    create_nitro_image
};
use log::debug;

use std::fs;
use std::io::Write;

pub struct EnclaveImageBuilder<'a> {
    pub client_image : String,

    pub client_cmd : Vec<String>,

    pub dir : &'a file::TempDir<'a>
}

impl<'a> EnclaveImageBuilder<'a> {

    pub fn nitro_image_name(&self) -> String {
        self.enclave_image_name() + ".eif"
    }

    pub fn create_image(&self, docker_util : &DockerUtil) -> Result<(), String> {
        let enclave_image_name = self.enclave_image_name();
        let enclave_image_tar_path = self.enclave_image_tar_path();
        let nitro_image_path = file::full_path(self.dir.0, &self.nitro_image_name());

        debug!("Creating enclave prerequisites!");
        self.create_requisites()?;

        debug!("Creating enclave image using buildkit!");
        docker_util.create_image(self.dir.0, &enclave_image_name)?;

        debug!("Loading enclave image into local docker repository!");
        //r.block_on(docker_util.load_image(&enclave_image_tar_path))?;

        debug!("Creating nitro image!");
        create_nitro_image(&enclave_image_name, &nitro_image_path)?;
        debug!("Nitro image has been created!");

        Ok(())
    }

    fn enclave_image_name(&self) -> String {
        self.client_image.clone() + "-enclave"
    }

    fn enclave_image_tar_path(&self) -> String {
        let enclave_image_tar = self.enclave_image_name() + ".tar";

        file::full_path(self.dir.0, &enclave_image_tar)
    }

    const enclave_requisites : &'a[&'a str] = &["start-enclave.sh", "vsock-proxy"];

    fn resources(&self) -> Vec<file::Resource> {
        vec![
            file::Resource {
                name: "start-enclave.sh".to_string(),
                data: include_bytes!("resources/enclave/start-enclave.sh").to_vec(),
            }
        ]
    }

    fn create_requisites(&self) -> Result<(), String> {
        file::create_docker_file(
            self.dir.0,
            &self.client_image,
            &EnclaveImageBuilder::enclave_requisites.join(" "),
            "./start-enclave.sh")?;

        file::create_resources(&self.resources(), self.dir.0)?;

        self.create_enclave_startup_script()?;

        Ok(())
    }

    fn create_enclave_startup_script(&self) -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(file::full_path(self.dir.0, "start-enclave.sh"))
            .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

        let cmd = self.client_cmd.join(" ");

        file.write_all(cmd.as_bytes()).map_err(|err| format!("Failed to write to file {:?}", err))?;

        Ok(())
    }
}

pub struct ParentImageBuilder<'a> {
    pub client_image : String,

    pub nitro_file : String,

    pub dir : &'a file::TempDir<'a>
}

impl<'a> ParentImageBuilder<'a> {

    pub fn create_image(&self, docker_util : &DockerUtil) -> Result<(), String> {
        let parent_image_name = self.client_image.clone() + "-parent";

        debug!("Creating parent prerequisites!");
        self.create_requisites()?;

        debug!("Creating parent image!");
        docker_util.create_image(self.dir.0, &parent_image_name)?;
        debug!("Parent image has been created!");

        Ok(())
    }

    fn create_requisites(&self) -> Result<(), String> {
        let all_requisites = {
            let mut result = ParentImageBuilder::parent_requisites.to_vec();
            result.push(&self.nitro_file);
            result
        };

        file::create_docker_file(
            self.dir.0,
            &self.client_image,
            &all_requisites.join(" "),
            "./start-parent.sh")?;

        file::create_resources(&self.resources(), self.dir.0)?;

        self.create_parent_startup_script()?;

        Ok(())
    }

    fn create_parent_startup_script(&self) -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(file::full_path(self.dir.0, "start-parent.sh"))
            .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

        let cmd = format!("nitro-cli run-enclave --eif-path {} --enclave-cid 4 --cpu-count 2 --memory 1124 --debug-mode", self.nitro_file);

        file.write_all(cmd.as_bytes()).map_err(|err| format!("Failed to write to file {:?}", err))?;

        Ok(())
    }

    const parent_requisites : &'a[&'a str] = &["start-parent.sh", "vsock-proxy"];

    fn resources(&self) -> Vec<file::Resource> {
        vec![
            file::Resource {
                name: "start-parent.sh".to_string(),
                data: include_bytes!("resources/parent/start-parent.sh").to_vec(),
            }
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
