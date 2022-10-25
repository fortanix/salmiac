use crate::{ConverterError, ConverterErrorKind, DockerReference, Result};
use api_model::shared::{UserProgramConfig, WorkingDir};
use shiplift::image::ImageDetails;

use std::ops::Deref;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::Sender;

pub struct ImageWithDetails<'a> {
    pub reference: DockerReference<'a>,

    pub details: ImageDetails,
}

impl<'a> ImageWithDetails<'a> {
    pub fn create_user_program_config(&self) -> Result<UserProgramConfig> {
        let config = &self.details.config;

        let (entry_point, arguments) = if let Some(ref raw_entry_point) = config.entrypoint {
            let (entry_point, mut entry_point_arguments) =
                ImageWithDetails::extract_entry_point_with_arguments(raw_entry_point)?;

            let mut cmd_argument_list = config.cmd.as_ref().unwrap_or(&Vec::new()).clone();

            entry_point_arguments.append(&mut cmd_argument_list);

            (entry_point, entry_point_arguments)
        } else {
            let cmd = config.cmd.as_ref().ok_or(ConverterError {
                message: "Input image must have a CMD clause if ENTRYPOINT is not present.".to_string(),
                kind: ConverterErrorKind::BadRequest,
            })?;

            ImageWithDetails::extract_entry_point_with_arguments(cmd)?
        };

        Ok(UserProgramConfig {
            entry_point,
            arguments,
            working_dir: self.working_dir(),
        })
    }

    pub(crate) fn working_dir(&self) -> WorkingDir {
        WorkingDir::from(self.details.config.working_dir.clone())
    }

    pub(crate) fn make_temporary(self, kind: ImageKind, sender: Sender<ImageToClean>) -> TempImage<'a> {
        TempImage {
            image: self,
            kind,
            sender,
        }
    }

    // Extracts first 12 unique bytes of id
    pub(crate) fn short_id(&self) -> &str {
        let id = &self.details.id;

        if id.starts_with("sha256:") {
            &id[7..19]
        } else {
            &id[..12]
        }
    }

    fn extract_entry_point_with_arguments(command: &Vec<String>) -> Result<(String, Vec<String>)> {
        if command.is_empty() {
            return Err(ConverterError {
                message: "CMD OR ENTRYPOINT cannot be empty".to_string(),
                kind: ConverterErrorKind::BadRequest,
            });
        }

        if command.len() > 1 {
            Ok((command[0].clone(), command[1..].to_vec()))
        } else {
            Ok((command[0].clone(), Vec::new()))
        }
    }
}

// An image that deletes itself from a local docker repository
// when it goes out of scope
pub(crate) struct TempImage<'a> {
    pub(crate) image: ImageWithDetails<'a>,

    pub(crate) kind: ImageKind,

    pub(crate) sender: mpsc::Sender<ImageToClean>,
}

impl<'a> Drop for TempImage<'a> {
    fn drop(&mut self) {
        let result = ImageToClean {
            name: self.image.reference.to_string(),
            kind: self.kind.clone(),
        };

        if let Err(e) = self.sender.send(result) {
            log::warn!(
                "Failed sending image {} to resource cleaner task. {:?}",
                self.image.reference,
                e
            );
        }
    }
}

impl<'a> Deref for TempImage<'a> {
    type Target = ImageWithDetails<'a>;

    fn deref(&self) -> &Self::Target {
        &self.image
    }
}

pub(crate) struct ImageToClean {
    pub(crate) name: String,

    pub(crate) kind: ImageKind,
}

#[derive(Eq, Hash, PartialEq, Clone, Debug, Ord, PartialOrd)]
pub enum ImageKind {
    Input,
    Intermediate,
    Result,
}

impl FromStr for ImageKind {
    type Err = String;

    fn from_str(input: &str) -> std::result::Result<ImageKind, Self::Err> {
        match &*input.trim().to_lowercase() {
            "input" => Ok(ImageKind::Input),
            "intermediate" => Ok(ImageKind::Intermediate),
            "result" => Ok(ImageKind::Result),
            _ => Err(format!("Unknown ImageType enum value: '{}'", input).to_string()),
        }
    }
}

pub(crate) fn docker_reference(image: &str) -> Result<DockerReference> {
    DockerReference::from_str(image).map_err(|err| ConverterError {
        message: err.to_string(),
        kind: ConverterErrorKind::BadRequest,
    })
}

pub(crate) fn output_docker_reference(image: &str) -> Result<DockerReference> {
    docker_reference(image).and_then(|e| {
        if e.tag().is_none() || e.has_digest() {
            Err(ConverterError {
                message: "Output image must have a tag and have no digest!".to_string(),
                kind: ConverterErrorKind::BadRequest,
            })
        } else {
            Ok(e)
        }
    })
}
