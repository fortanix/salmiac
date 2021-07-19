use std::fs;
use std::io::Write;
use log::{
    error
};
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;

pub fn full_path(dir : &str, file : &str) -> String {
    format!("{}/{}", dir, file)
}

pub struct Resource {
    pub name : String,

    pub data : Vec<u8>
}

pub fn create_resources(resources : &Vec<Resource>, dir : &str) -> Result<(), String> {
    for resource in resources {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(full_path(dir, &resource.name))
            .map_err(|err| format!("Failed to create resource {}, error: {:?}", &resource.name, err))?;

        file.write_all(&resource.data).map_err(|err| format!("Failed to create resource {}, error: {:?}", &resource.name, err))?;

        file.set_execute().map_err(|err| format!("Cannot change permissions for a file {:?}", err))?;
    }

    Ok(())
}

// A directory that deletes itself on drop
pub struct TempDir<'a>(pub &'a str);

impl<'a> TempDir<'a> {
    pub fn new(name : &'a str) -> Result<Self, String> {
        if fs::metadata(name).is_ok() {
            fs::remove_dir_all(name).map_err(|err| format!("Cannot delete dir {:?}", err))?;
        }

        fs::create_dir(name)
            .map_err(|err| format!("Cannot create dir, reason {:?}", err))
            .map(|_| { TempDir(name) })
    }
}

impl Drop for TempDir<'_> {
    fn drop(&mut self) {
        match fs::remove_dir_all(self.0.clone()) {
            Ok(_) => {}
            Err(err) => {
                error!("{}", format!("Cannot delete dir {} , reason : {:?}", self.0, err))
            }
        }
    }
}

pub fn create_work_dir<'a>(name : &'a str, resources : &Vec<Resource>) -> Result<TempDir<'a>, String> {
    let result = TempDir::new(name)?;

    create_resources(resources, result.0)?;

    Ok(result)
}

pub fn create_docker_file<'a>(dir: &str, image_name : &str, copy : &str, cmd : &str) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(format!("{}/{}", dir, "Dockerfile"))
        .map_err(|err| format!("Failed to create docker file {:?}", err))?;

    let filled_contents = format!(
        "FROM {} \n\
         COPY {} ./ \n\
         CMD  {} \n",
        image_name,
        copy,
        cmd
    );

    file.write_all(filled_contents.as_bytes()).map_err(|err| format!("Failed to write to file {:?}", err))?;

    Ok(())
}

pub trait UnixFile {
    fn set_execute(&mut self) -> std::io::Result<()>;
}

impl UnixFile for fs::File {
    fn set_execute(&mut self) -> std::io::Result<()> {
        self.set_permissions(Permissions::from_mode(0o755))
    }
}
