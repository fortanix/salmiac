use tempfile::TempDir;
use log::info;
use docker_image_reference::{Reference as DockerReference};
use model_types::HexString;
use api_model::{NitroEnclavesConversionRequest, NitroEnclavesConversionResponse, ConvertedImageInfo, NitroEnclavesConfig, NitroEnclavesMeasurements, CertificateConfig, NitroEnclavesVersion, HashAlgorithm};
use crate::image::{DockerUtil};
use crate::image_builder::{EnclaveImageBuilder, ParentImageBuilder};

use std::fmt;
use std::error::Error;
use std::collections::HashMap;
use std::env;

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

pub async fn run(args: NitroEnclavesConversionRequest) -> Result<NitroEnclavesConversionResponse> {
    if args.request.input_image.name == args.request.output_image.name {
        return Err(ConverterError {
            message: "Input and output images must be different".to_string(),
            kind: ConverterErrorKind::BadRequest
        })
    }
    let input_image_reference = docker_reference(&args.request.input_image.name)?;
    let output_image_reference = output_docker_reference(&args.request.output_image.name)?;

    let input_repository = DockerUtil::new(&args.request.input_image.auth_config);

    info!("Retrieving client image!");
    let input_image = input_repository.get_image(&input_image_reference)
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::ImagePull
        })?;

    info!("Retrieving CMD from client image!");
    let client_cmd = input_image.details
        .config
        .cmd
        .ok_or(ConverterError {
            message: "Input image has no CMD clause.".to_string(),
            kind: ConverterErrorKind::BadRequest
        })?;

    if client_cmd.len() < 3 || !(client_cmd[0] == "/bin/sh" && client_cmd[1] == "-c") {
        return Err(ConverterError {
            message: "Input is not in the form of /bin/sh -c <client arguments>.".to_string(),
            kind: ConverterErrorKind::BadRequest
        })
    }

    info!("Creating working directory!");
    let temp_dir = TempDir::new().map_err(|err| ConverterError {
        message: format!("Cannot create temp dir {:?}", err),
        kind: ConverterErrorKind::RequisitesCreation
    })?;

    let certificate_settings = args.request.converter_options
        .certificates
        .first()
        .map(|e| e.clone())
        .unwrap_or(default_certificate_config());

    let enclave_builder = EnclaveImageBuilder {
        client_image: args.request.input_image.name.clone(),
        client_cmd,
        dir : &temp_dir,
        certificate_settings
    };

    info!("Building enclave image!");
    let nitro_image_result = enclave_builder.create_image(&input_repository).await?;
    let parent_image = env::var("PARENT_IMAGE").unwrap_or(PARENT_IMAGE.to_string());

    let parent_builder = ParentImageBuilder {
        output_image : args.request.output_image.name.clone(),
        parent_image,
        nitro_file : nitro_image_result.nitro_file,
        dir : &temp_dir,
        start_options: args.nitro_enclaves_options
    };

    info!("Building parent image!");
    parent_builder.create_image(&input_repository).await?;

    info!("Resulting image has been successfully created!");
    let result_image = input_repository.get_image(&output_image_reference)
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::ImagePull
        })?;

    let result_repository = DockerUtil::new(&args.request.output_image.auth_config);

    info!("Pushing resulting image to {}!", output_image_reference.to_string());
    result_repository.push_image(&result_image, &output_image_reference)
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

    let result_sha = image_short_id(&result_image.details.id);

    let result = NitroEnclavesConversionResponse {
        converted_image: ConvertedImageInfo {
            name: args.request.output_image.name,
            sha: HexString::new(result_sha),
            size: result_image.details.size as usize
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

fn default_certificate_config() -> CertificateConfig {
    let mut result= CertificateConfig::new();

    result.key_path = Some("key".to_string());
    result.cert_path = Some("cert".to_string());

    result
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
