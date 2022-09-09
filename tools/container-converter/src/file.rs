use log::debug;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::borrow::Borrow;

#[derive(Clone)]
pub struct Resource<'a> {
    pub name: &'a str,

    pub data: &'a [u8],

    pub is_executable: bool,
}

pub fn create_resources(resources: &[Resource], dir: &Path) -> Result<(), String> {
    for resource in resources {
        let mut file = fs::File::create(dir.join(&resource.name))
            .map_err(|err| format!("Failed to create resource {}, error: {:?}", &resource.name, err))?;

        file.write_all(&resource.data)
            .map_err(|err| format!("Failed to create resource {}, error: {:?}", &resource.name, err))?;

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
        .truncate(true)
        .write(true)
        .open(dir.join("Dockerfile"))
        .map_err(|err| format!("Failed to create docker file at {}. {:?}", dir.display(), err))
}

pub fn log_docker_file(dir: &Path) -> Result<(), String> {
    log_file(&*dir.join("Dockerfile"))
}

pub fn log_file(path: &Path) -> Result<(), String> {
    let file_name = path.file_name().and_then(|e| e.to_str()).unwrap_or("<Unknown file>");

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

/// A type that describes docker file contents by section 
pub(crate) struct DockerFile<'a, T: AsRef<str> + Borrow<str>, V: AsRef<str> + Borrow<str>> {
    pub from: &'a str,

    pub add: Option<DockerCopyArgs<'a, V>>,

    pub env: &'a [T],

    pub cmd: Option<&'a str>,

    pub entrypoint: Option<&'a str>
}

impl<'a, T: AsRef<str> + Borrow<str>, V: AsRef<str> + Borrow<str>> ToString for DockerFile<'a, T, V> {
    fn to_string(&self) -> String {
        let mut result = format!("FROM {} \n", self.from);

        if let Some(add) = &self.add {
            result.push_str(&format!("ADD {} \n", add.to_string()));
        }

        if !self.env.is_empty() {
            result.push_str(&format!("ENV {} \n", self.env.join(" ")));
        }

        if let Some(cmd) = &self.cmd {
            result.push_str(&format!("CMD {} \n", cmd));
        }

        if let Some(entrypoint) = &self.entrypoint {
            result.push_str(&format!("ENTRYPOINT [\"{}\"] \n", entrypoint));
        }

        result
    }
}

pub(crate) struct DockerCopyArgs<'a, T: AsRef<str> + Borrow<str>> {
    pub items: &'a [T],

    pub destination: String,
}

impl<'a, T: AsRef<str> + Borrow<str>> ToString for DockerCopyArgs<'a, T> {
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
