use log::debug;

use std::fs;
use std::io::{Write, BufReader, BufRead};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub struct Resource {
    pub name : String,

    pub data : Vec<u8>,

    pub is_executable : bool
}

pub fn create_resources(resources : &Vec<Resource>, dir : &Path) -> Result<(), String> {
    for resource in resources {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(&resource.name))
            .map_err(|err| format!("Failed to create resource {}, error: {:?}", &resource.name, err))?;

        file.write_all(&resource.data).map_err(|err| format!("Failed to create resource {}, error: {:?}", &resource.name, err))?;

        if resource.is_executable {
            file.set_execute()
                .map_err(|err| format!("Cannot change permissions for a file {:?}", err))?;
        }
    }

    Ok(())
}

pub fn create_docker_file(dir: &Path) -> Result<fs::File, String> {
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(dir.join("Dockerfile"))
        .map_err(|err| format!("Failed to create docker file at {}. {:?}", dir.display(), err))
}

pub fn populate_docker_file(file : &mut fs::File, image_name : &str, copy : &DockerCopyArgs, cmd : &str, env : &str) -> Result<(), String> {
    let filled_contents = format!(
        "FROM {} \n\
         COPY {} ./ \n\
         ENV {} \n\
         CMD  {} \n",
        image_name,
        copy.to_string(),
        env,
        cmd
    );

    file.write_all(filled_contents.as_bytes())
        .map_err(|err| format!("Failed to write to file {:?}", err))
}

pub fn log_docker_file(dir : &Path) -> Result<(), String> {
    log_file(&*dir.join("Dockerfile"))
}

pub fn log_file(path : &Path) -> Result<(), String> {
    let file_name = path.file_name()
        .and_then(|e| e.to_str())
        .unwrap_or("<Unknown file>");

    let file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|err| format!("Failed to open file {} {:?}", file_name, err))?;

    let reader = BufReader::new(file);

    debug!("File contents of {}:\n", file_name);
    for line in reader.lines() {
        if let Ok(l) = line {
            println!("{}", l)
        }
    }

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
