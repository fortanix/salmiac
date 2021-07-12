use std::fs;
use std::io::Write;
use log::{
    error
};

pub fn full_path(dir : &str, file : &str) -> String {
    format!("{}/{}", dir, file)
}

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
pub fn create_work_dir(name : &str) -> Result<TempDir, String> {
    let result = TempDir::new(name)?;

    let from = full_path("resources/enclave", "vsock-proxy");
    let to = full_path(&result.0, "vsock-proxy");

    fs::copy(from, to).map_err(|err| format!("Failed to copy vsock-proxy bin {:?}", err))?;

    Ok(result)
}

pub fn create_docker_file<'a>(dir: &str, image_name : &str, copy : &str, cmd : &str) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
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