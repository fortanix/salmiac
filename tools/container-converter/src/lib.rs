pub mod image;
pub mod file;

use image::{
    DockerUtil,
    create_nitro_image
};
use tokio::runtime::Runtime;

use std::fs;
use std::io::Write;


pub struct EnclaveImageBuilder<'a> {
    pub client_image : String,

    pub client_cmd : Vec<String>,

    pub dir : &'a file::TempDir<'a>
}

impl<'a> EnclaveImageBuilder<'a> {

    fn enclave_image_name(&self) -> String {
        self.client_image.clone() + "-enclave"
    }

    fn enclave_image_tar_path(&self) -> String {
        let enclave_image_tar = self.enclave_image_name() + ".tar";

        file::full_path(self.dir.0, &enclave_image_tar)
    }

    pub fn nitro_image_name(&self) -> String {
        self.enclave_image_name() + ".eif"
    }

    fn nitro_image_path(&self) -> String {
        file::full_path(self.dir.0, &self.nitro_image_name())
    }

    fn startup_tmp_dir_path(&self) -> String {
        file::full_path(self.dir.0, "start-enclave.sh")
    }

    fn startup_resources_path(&self) -> String {
        file::full_path("resources/enclave", "start-enclave.sh")
    }

    pub fn create_image(&self, docker_util : &DockerUtil, r : Runtime) -> Result<(), String> {
        let enclave_image_name = self.enclave_image_name();
        let enclave_image_tar_path = self.enclave_image_tar_path();
        let nitro_image_path = self.nitro_image_path();

        self.create_requisites()?;

        docker_util.create_image_buildkit(self.dir.0, &enclave_image_name)?;

        r.block_on(docker_util.load_image(&enclave_image_tar_path))?;

        create_nitro_image(&enclave_image_name, &nitro_image_path)?;

        Ok(())
    }

    fn create_requisites(&self) -> Result<(), String> {
        file::create_docker_file(
            self.dir.0,
            &self.client_image,
            "start-enclave.sh vsock-proxy",
            "./start-enclave.sh")?;

        self.create_enclave_startup_script()?;

        Ok(())
    }

    fn create_enclave_startup_script(&self) -> Result<(), String> {
        let from = self.startup_resources_path();
        let to = self.startup_tmp_dir_path();

        fs::copy(from, &to).map_err(|err| format!("Failed to copy base startup script {:?}", err))?;

        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(to)
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

    fn parent_image_name(&self) -> String {
        self.client_image.clone() + "-parent"
    }

    fn startup_tmp_dir_path(&self) -> String {
        file::full_path(self.dir.0, "start-parent.sh")
    }

    fn startup_resources_path(&self) -> String {
        file::full_path("resources/parent", "start-parent.sh")
    }

    pub fn create_image(&self, docker_util : &DockerUtil) -> Result<(), String> {
        let parent_image_name = self.parent_image_name();

        self.create_requisites()?;

        docker_util.create_image_buildkit(self.dir.0, &parent_image_name)?;
        
        Ok(())
    }

    fn create_requisites(&self) -> Result<(), String> {
        let copy = self.nitro_file.clone() + " start-parent.sh";

        file::create_docker_file(self.dir.0, &self.client_image, &copy, "./start-parent.sh")?;

        self.create_parent_startup_script()?;

        Ok(())
    }

    fn create_parent_startup_script(&self) -> Result<(), String> {
        let from = self.startup_resources_path();
        let to = self.startup_tmp_dir_path();

        fs::copy(from, &to)
            .map_err(|err| format!("Failed to copy base startup script {:?}", err))?;

        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(to)
            .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

        let cmd = format!("nitro-cli run-enclave --eif-path {} --enclave-cid 4 --cpu-count 2 --memory 1124 --debug-mode", self.nitro_file);

        file.write_all(cmd.as_bytes()).map_err(|err| format!("Failed to write to file {:?}", err))?;

        Ok(())
    }
}
