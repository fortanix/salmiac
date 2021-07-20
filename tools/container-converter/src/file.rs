use tempfile::TempDir;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn full_path(dir : &str, file : &str) -> String {
    format!("{}/{}", dir, file)
}

pub struct Resource {
    pub name : String,

    pub data : Vec<u8>
}

pub fn create_resources(resources : &Vec<Resource>, dir : &Path) -> Result<(), String> {
    for resource in resources {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(&resource.name))
            .map_err(|err| format!("Failed to create resource {}, error: {:?}", &resource.name, err))?;

        file.write_all(&resource.data).map_err(|err| format!("Failed to create resource {}, error: {:?}", &resource.name, err))?;

        file.set_execute().map_err(|err| format!("Cannot change permissions for a file {:?}", err))?;
    }

    Ok(())
}

pub fn create_work_dir(resources : &Vec<Resource>) -> Result<TempDir, String> {
    let result = TempDir::new().map_err(|err| format!("Cannot create temp dir {:?}", err))?;

    create_resources(resources, result.path())?;

    Ok(result)
}

pub fn create_docker_file(dir: &Path) -> Result<fs::File, String> {
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(dir.join("Dockerfile"))
        .map_err(|err| format!("Failed to create docker file {:?}", err))
}

pub fn populate_docker_file(file : &mut fs::File, image_name : &str, copy : &DockerCopyArgs, cmd : &str) -> Result<(), String> {
    let filled_contents = format!(
        "FROM {} \n\
         COPY {} ./ \n\
         CMD  {} \n",
        image_name,
        copy.to_string(),
        cmd
    );

    file.write_all(filled_contents.as_bytes()).map_err(|err| format!("Failed to write to file {:?}", err))?;

    Ok(())
}

pub struct DockerCopyArgs {
    pub items : Vec<String>,

    pub destination : String
}

impl DockerCopyArgs {
    pub fn copy_to_home(items : Vec<String>) -> Self {
        DockerCopyArgs {
            items,
            destination: "./".to_string()
        }
    }

    fn to_string(&self) -> String {
        format!("{} {}", self.items.join(" "), self.destination)
    }
}

pub trait UnixFile {
    fn set_execute(&mut self) -> std::io::Result<()>;
}

impl UnixFile for fs::File {
    fn set_execute(&mut self) -> std::io::Result<()> {
        self.set_permissions(fs::Permissions::from_mode(0o755))
    }
}
