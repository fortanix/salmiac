use std::fs;
use log::{
    error
};

pub struct RichFile<'a> {
    pub file : fs::File,

    pub path : &'a str
}

pub struct TempFile<'a>(pub RichFile<'a>);

impl Drop for TempFile<'_> {
    fn drop(&mut self) {
        match fs::remove_file(self.0.path.clone()) {
            Ok(_) => {}
            Err(err) => {
                error!("{}", format!("Cannot delete file , reason : {:?}", err))
            }
        }
    }
}