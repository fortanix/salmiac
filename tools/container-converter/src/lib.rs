use tempfile::TempDir;
use log::{info, debug, warn};
use docker_image_reference::{Reference as DockerReference};
use shiplift::{Image, Docker};

use model_types::HexString;
use api_model::{NitroEnclavesConversionRequest, NitroEnclavesConversionResponse, ConvertedImageInfo, NitroEnclavesConfig, NitroEnclavesMeasurements, NitroEnclavesVersion, HashAlgorithm, AuthConfig};
use api_model::shared::EnclaveSettings;
use crate::image::{DockerUtil};
use crate::image_builder::{EnclaveImageBuilder, ParentImageBuilder};

use std::fmt;
use std::error::Error;
use std::collections::HashMap;
use std::env;
use std::sync::mpsc;
use std::rc::Rc;
use std::sync::mpsc::Sender;


pub mod image;
pub mod file;
pub mod image_builder;

pub type Result<T> = std::result::Result<T, ConverterError>;

#[derive(Debug)]
pub struct ConverterError {
    pub message : String,

    pub kind : ConverterErrorKind
}

#[derive(Debug)]
pub enum ConverterErrorKind {
    ImagePull,
    ImagePush,
    RequisitesCreation,
    EnclaveImageCreation,
    NitroFileCreation,
    ParentImageCreation,
    BadRequest
}

impl fmt::Display for ConverterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(message : {}, kind : {:?})", self.message, self.kind)
    }
}

impl Error for ConverterError { }

const PARENT_IMAGE : &str = "parent-base";

async fn delete_docker_images(docker : Docker, receiver: mpsc::Receiver<String>) -> Result<()> {
    let mut images : Vec<String> = Vec::new();

    while let Ok(image_name) = receiver.recv() {
        images.push(image_name)
    }

    for image_name in images {
        let image_interface = Image::new(&docker, image_name.clone());

        match image_interface.delete().await {
            Ok(_) => {
                info!("Successfully cleaned intermediate image {}", image_name);
            }
            Err(e) => {
                warn!("Error cleaning intermediate image {}. {:?}", image_name, e);
            }
        }
    }

    Ok(())
}

pub async fn run(args: NitroEnclavesConversionRequest) -> Result<NitroEnclavesConversionResponse> {
    let (sender, receiver) = mpsc::channel();
    let local_repository = Docker::new();

    let resource_cleaner = tokio::spawn(delete_docker_images(local_repository, receiver));
    let converter = run0(args, Rc::new(sender));

    let (result, _) = tokio::join!(converter, resource_cleaner);

    result
}

pub async fn run0(args: NitroEnclavesConversionRequest, sender : Rc<Sender<String>>) -> Result<NitroEnclavesConversionResponse> {
    if args.request.input_image.name == args.request.output_image.name {
        return Err(ConverterError {
            message: "Input and output images must be different".to_string(),
            kind: ConverterErrorKind::BadRequest
        })
    }

    info!("Retrieving requisite image!");
    get_parent_base_image().await?;

    let client_image = docker_reference(&args.request.input_image.name)?;
    let output_image_reference = output_docker_reference(&args.request.output_image.name)?;

    let input_repository = DockerUtil::new(&args.request.input_image.auth_config);

    info!("Retrieving client image!");
    let input_image_result = input_repository.get_image(&client_image)
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::ImagePull
        })?;
    let input_image = input_image_result.make_temporary(sender.clone());

    info!("Creating working directory!");
    let temp_dir = TempDir::new().map_err(|err| ConverterError {
        message: format!("Cannot create temp dir {:?}", err),
        kind: ConverterErrorKind::RequisitesCreation
    })?;
    
    let user_program_config = input_image.0.create_user_program_config()?;
    debug!("User program config is: {:?}", user_program_config);

    let enclave_builder = EnclaveImageBuilder {
        client_image,
        dir : &temp_dir,
    };

    info!("Building enclave image!");
    let enclave_settings = EnclaveSettings {
        user_program_config,
        certificate_config: args.request.converter_options.certificates
    };
    let nitro_image_result = enclave_builder.create_image(&input_repository, enclave_settings).await?;

    let parent_image = env::var("PARENT_IMAGE").unwrap_or(PARENT_IMAGE.to_string());

    let parent_builder = ParentImageBuilder {
        output_image : args.request.output_image.name.clone(),
        parent_image,
        nitro_file : nitro_image_result.nitro_file,
        dir : &temp_dir,
        start_options: args.nitro_enclaves_options
    };
    let _ = nitro_image_result.enclave_image.make_temporary(sender.clone());

    info!("Building parent image!");
    parent_builder.create_image(&input_repository).await?;

    info!("Resulting image has been successfully created!");
    let result_image_result = input_repository.get_image(&output_image_reference)
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::ImagePull
        })?;
    let result_image = result_image_result.make_temporary(sender.clone());

    let result_repository = DockerUtil::new(&args.request.output_image.auth_config);

    info!("Pushing resulting image to {}!", output_image_reference.to_string());
    result_repository.push_image(&result_image.0, &output_image_reference)
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::ImagePush
        })?;

    info!("Resulting image has been successfully pushed to {} !", output_image_reference.to_string());

    let mut measurements = HashMap::new();

    measurements.insert(NitroEnclavesVersion::NitroEnclaves, NitroEnclavesMeasurements {
        hash_algorithm: HashAlgorithm::Sha384,
        pcr0: HexString::new(nitro_image_result.pcr_list.pcr0),
        pcr1: HexString::new(nitro_image_result.pcr_list.pcr1),
        pcr2: HexString::new(nitro_image_result.pcr_list.pcr2)
    });

    let result_sha = image_short_id(&result_image.0.details.id);

    let result = NitroEnclavesConversionResponse {
        converted_image: ConvertedImageInfo {
            name: args.request.output_image.name,
            sha: HexString::new(result_sha),
            size: result_image.0.details.size as usize
        },

        config: NitroEnclavesConfig {
            measurements,
            pcr8: HexString::new(nitro_image_result.pcr_list.pcr8.unwrap_or(String::new()))
        }
    };

    Ok(result)
}

// Extracts first 12 unique bytes of id
fn image_short_id(id : &str) -> &str {
    if id.starts_with("sha256:") {
        &id[7..19]
    } else {
        &id[..12]
    }
}

fn docker_reference(image : &str) -> Result<DockerReference> {
    DockerReference::from_str(image)
        .map_err(|err| ConverterError {
            message: err.to_string(),
            kind: ConverterErrorKind::BadRequest
        })
}

fn output_docker_reference(image: &str) -> Result<DockerReference> {
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

async fn get_parent_base_image() -> Result<()> {
    let parent_image = env::var("PARENT_IMAGE").unwrap_or(PARENT_IMAGE.to_string());
    let username_var = env_var_or_none("PARENT_IMAGE_USERNAME");
    let password_var = env_var_or_none("PARENT_IMAGE_PASSWORD");

    let auth_config = match (username_var, password_var) {
        (Some(username), Some(password)) => {
            Some(AuthConfig {
                username,
                password,
            })
        }
        _ => {
            None
        }
    };

    let repository = DockerUtil::new(&auth_config);
    let parent_image_reference = DockerReference::from_str(&parent_image)
        .map_err(|err| {
            ConverterError {
                message: format!("Requisite image {} address has bad format. {:?}", parent_image, err),
                kind: ConverterErrorKind::BadRequest,
            }
        })?;

    let _result = repository.get_image(&parent_image_reference)
        .await
        .map_err(|message| ConverterError {
            message : format!("Failed retrieving requisite {} image. {:?}", parent_image, message),
            kind: ConverterErrorKind::ImagePull
        })?;

    Ok(())
}

fn env_var_or_none(var_name : &str) -> Option<String> {
    match env::var(var_name) {
        Ok(e) => {
            Some(e)
        }
        Err(err) => {
            warn!("Failed reading env var {}, assuming var is not set. {:?}", var_name, err);
            None
        }
    }
}
