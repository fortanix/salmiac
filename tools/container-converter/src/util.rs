use std::fs;
use log::{
    error
};

pub struct RichFile<'a> {
    pub file : fs::File,

    pub path : &'a str
}

// File that deletes itself on `Drop`
pub struct TempRichFile<'a>(pub RichFile<'a>);

impl Drop for TempRichFile<'_> {
    fn drop(&mut self) {
        match fs::remove_file(self.0.path.clone()) {
            Ok(_) => {}
            Err(err) => {
                error!("{}", format!("Cannot delete file {} , reason : {:?}", self.0.path, err))
            }
        }
    }
}

pub struct TempDir<'a>(pub &'a str);

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

pub struct TempFile<'a>(pub &'a str);

impl Drop for TempFile<'_> {
    fn drop(&mut self) {
        match fs::remove_file(self.0.clone()) {
            Ok(_) => {}
            Err(err) => {
                error!("{}", format!("Cannot delete file {} , reason : {:?}", self.0, err))
            }
        }
    }
}