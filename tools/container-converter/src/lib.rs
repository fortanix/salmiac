/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#[cfg(platform = "nitro")]
pub mod nitro;
#[cfg(platform = "simulator")]
pub mod simulator;
#[cfg(platform = "snp")]
pub mod snp;
#[cfg(platform = "tdx")]
pub mod tdx;

use std::collections::HashSet;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::mpsc::{self, Sender};
use std::{env, fmt};

use api_model::converter::{AuthConfig, ConversionRequest, ConverterOptions};
use api_model::enclave::{CcmBackendUrl, UserConfig, UserProgramConfig};
use api_model::HexString;
use async_process::{Command, Stdio};
use docker_image_reference::Reference as DockerReference;
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use shiplift::image::DeleteOptions;
use shiplift::{Docker, Image};
use tempfile::TempDir;

use crate::docker::{DockerDaemon, DockerUtil};
use crate::image::{
    docker_reference, output_docker_reference, ImageKind, ImageToClean, ImageWithDetails,
};
use crate::image_builder::enclave::{get_image_env, EnclaveSettings, GenericEnclaveImageBuilder};
use crate::image_builder::parent::ParentImageBuilder;

use crate::image_builder::enclave::PlatformEnclaveImageBuilder;
use crate::image_builder::parent::PlatformParentImageBuilder;
use api_model::PlatformConversionRequest;
use api_model::PlatformConversionResponse;

#[cfg(platform = "nitro")]
use crate::nitro::create_response;

#[cfg(platform = "snp")]
use crate::snp::create_response;
#[cfg(platform = "tdx")]
use crate::tdx::create_response;

#[cfg(platform = "simulator")]
use crate::simulator::create_response;

pub mod docker;
pub mod file;
pub mod image;
pub mod image_builder;

pub type Result<T> = std::result::Result<T, ConverterError>;

#[derive(Debug)]
pub struct ConverterError {
    pub message: String,

    pub kind: ConverterErrorKind,
}

#[derive(Debug, PartialEq)]
pub enum ConverterErrorKind {
    ImageGet,
    ImagePush,
    RequisitesCreation,
    EnclaveImageCreation,
    NitroFileCreation,
    ParentImageCreation,
    BadRequest,
    InternalError,
    BlockFileCreation,
    ImageFileSystemExport,
    ContainerCreation,
    BlockFileFull,
    BadCertConfig,
    BadCcmConfiguration,
    BadDsmConfiguration,
    DockerLoad,
}

impl fmt::Display for ConverterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(message : {}, kind : {:?})", self.message, self.kind)
    }
}

impl Error for ConverterError {}

#[cfg(platform = "nitro")]
const PARENT_IMAGE: &str = "parent-base-nitro";

#[cfg(platform = "snp")]
const PARENT_IMAGE: &str = "parent-base-snp";
#[cfg(platform = "tdx")]
const PARENT_IMAGE: &str = "parent-base-tdx";

#[cfg(platform = "simulator")]
const PARENT_IMAGE: &str = "parent-base-simulator";

const PARENT_IMAGE_PATH: &str = "parent-base.tar";

#[cfg(any(platform = "nitro", platform = "snp", platform = "tdx"))]
const ENCLAVE_IMAGE: &str = "enclave-base";

#[cfg(platform = "simulator")]
const ENCLAVE_IMAGE: &str = "enclave-base-simulator";

#[cfg(platform = "snp")]
const ENCLAVE_IMAGE_SNP_GPU: &str = "enclave-base-gpu";
#[cfg(platform = "tdx")]
const ENCLAVE_IMAGE_TDX_GPU: &str = "enclave-base-gpu";

const ENCLAVE_IMAGE_PATH: &str = "enclave-base.tar";

#[cfg(any(platform = "snp", platform = "tdx"))]
const ENCLAVE_GPU_IMAGE_PATH: &str = "enclave-base-gpu.tar";

const DEFAULT_RSA_SIZE: u32 = 3072;
const RSA_KEY_SIZES: [u32; 3] = [2048, DEFAULT_RSA_SIZE, 4096];

pub async fn process_request(request_file: &str) -> std::result::Result<(), String> {
    let request = serde_json::from_str::<PlatformConversionRequest>(&request_file)
        .map_err(|err| format!("Failed deserializing conversion request. {:?}", err))?;

    match run(request).await {
        Ok(response) => {
            let response_serialized = serde_json::to_string(&response)
                .map_err(|err| format!("Failed serializing conversion request. {:?}", err))?;

            println!("Successful conversion: {:?}", response_serialized);
            Ok(())
        }
        Err(err) => {
            error!("Converter exited with error: {}", err.message);
            Err(err.message)
        }
    }
}

pub async fn run(args: PlatformConversionRequest) -> Result<PlatformConversionResponse> {
    let (images_to_clean_snd, images_to_clean_rcv) = mpsc::channel();
    let local_repository = Docker::new();
    let preserve_images = preserve_images_list()?;

    let resource_cleaner = tokio::spawn(clean_docker_images(
        local_repository,
        images_to_clean_rcv,
        preserve_images,
    ));
    let converter = tokio::spawn(run0(args, images_to_clean_snd));

    let (result, _) = tokio::join!(converter, resource_cleaner);

    result.map_err(|err| ConverterError {
        message: format!("Join error in convert task. {:?}", err),
        kind: ConverterErrorKind::InternalError,
    })?
}

async fn run0(
    conversion_request: PlatformConversionRequest,
    images_to_clean_snd: Sender<ImageToClean>,
) -> Result<PlatformConversionResponse> {
    validate_request(&conversion_request.request)?;

    let mut parent_image = env::var("PARENT_IMAGE").ok();
    if let Some(s) = &parent_image {
        info!("Using parent base image from environment variable: {}", s);
    } else {
        info!(
            "Using parent base image from tar file: {}",
            PARENT_IMAGE_PATH
        );
    }

    info!("Retrieving requisite images!");
    get_parent_base_image(&mut parent_image).await?;

    let client_image = docker_reference(&conversion_request.request.input_image.name)?;

    let input_repository = DockerDaemon::new(&conversion_request.request.input_image.auth_config);

    info!("Retrieving client image!");
    let input_image = input_repository
        .get_latest_image_details(&client_image)
        .await
        .map(|details| {
            ImageWithDetails {
                reference: client_image,
                details,
            }
            .make_temporary(ImageKind::Input, images_to_clean_snd.clone())
        })
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::ImageGet,
        })?;

    info!("Creating working directory!");
    let temp_dir = TempDir::new().map_err(|err| ConverterError {
        message: format!("Cannot create temp dir {:?}", err),
        kind: ConverterErrorKind::RequisitesCreation,
    })?;

    info!("Building enclave image!");
    let image_result = {
        let enclave_base_image_path_str = PlatformEnclaveImageBuilder::get_enclave_base_details(
            &conversion_request.enclaves_options,
        );

        let mut enclave_base_image = env::var("ENCLAVE_IMAGE").ok();
        if let Some(s) = &enclave_base_image {
            info!("Using enclave base image from environment variable: {}", s);
        } else {
            info!(
                "Using enclave base image from tar file: {}",
                enclave_base_image_path_str
            );
        }

        let enclave_base_image =
            get_enclave_base_image(&mut enclave_base_image, enclave_base_image_path_str).await?;

        let user_program_config = create_user_program_config(
            &conversion_request.request.converter_options,
            &input_image.image,
        )?;

        debug!("User program config is: {:?}", user_program_config);

        let enclave_builder = PlatformEnclaveImageBuilder {
            enclave_image_builder: GenericEnclaveImageBuilder {
                client_image_reference: &input_image.image.reference,
                dir: &temp_dir,
                enclave_base_image: &enclave_base_image.reference,
            },
        };

        let enclave_settings = EnclaveSettings::new(
            &input_image,
            &conversion_request.request.converter_options,
            #[cfg(any(platform = "snp", platform = "tdx"))]
            &conversion_request.enclaves_options,
        );
        let image_env_vars =
            get_image_env(&input_image, &conversion_request.request.converter_options);
        let user_config = UserConfig {
            user_program_config,
            certificate_config: conversion_request.request.converter_options.certificates,
        };

        let sender = images_to_clean_snd.clone();
        enclave_builder
            .create_image(
                &input_repository,
                enclave_settings,
                user_config,
                image_env_vars,
                sender,
            )
            .await?
    };

    let parent_builder = PlatformParentImageBuilder {
        parent_image_builder: ParentImageBuilder {
            parent_image: parent_image.expect("parent_image should not be None at this point"),
            dir: &temp_dir,
        },
        start_options: conversion_request.enclaves_options,
    };

    info!("Building result image!");
    let output_image = output_docker_reference(&conversion_request.request.output_image.name)?;
    let result = parent_builder
        .create_image(&input_repository, output_image)
        .await
        .map(|e| e.make_temporary(ImageKind::Result, images_to_clean_snd.clone()))?;

    if conversion_request
        .request
        .converter_options
        .push_converted_image
        .unwrap_or(true)
    {
        info!("Attempting to push output image");
        push_result_image(
            &result.image,
            &conversion_request.request.output_image.auth_config,
        )
        .await?;
    } else {
        info!("Skipping output image push");
    }

    create_response(&result.image, image_result)
}

fn validate_request(request: &ConversionRequest) -> Result<()> {
    if request.input_image.name == request.output_image.name {
        return Err(ConverterError {
            message: "Input and output images must be different".to_string(),
            kind: ConverterErrorKind::BadRequest,
        });
    }

    if !request.converter_options.certificates.is_empty() {
        for cert_settings in &request.converter_options.certificates {
            if let Some(kp) = &cert_settings.key_param {
                let key_size = kp.as_u64().unwrap_or(DEFAULT_RSA_SIZE.into());
                // If a certificate is configured and it contains a valid number, it should
                // be one of the RSA_KEY_SIZES that is supported.
                if !RSA_KEY_SIZES.contains(&(key_size as u32)) {
                    return Err(ConverterError {
                        message: format!(
                            "Key param {:?} of certificate is not supported",
                            key_size
                        ),
                        kind: ConverterErrorKind::BadCertConfig,
                    });
                }
            }

            if let Some(_s) = &cert_settings.chain_path {
                return Err(ConverterError {
                    message: "Chain path is not supported on this platform yet".to_string(),
                    kind: ConverterErrorKind::BadCertConfig,
                });
            }
        }
    }

    if !request.converter_options.ca_certificates.is_empty() {
        return Err(ConverterError {
            message: "CA certificates are not supported on this platform yet".to_string(),
            kind: ConverterErrorKind::BadCertConfig,
        });
    }

    if let Some(c) = &request.converter_options.ccm_configuration {
        if CcmBackendUrl::new(c.ccm_url.as_str()).is_err() {
            return Err(ConverterError {
                message: "CcmConfiguration:ccm_url should be in <host>:<port> format".to_string(),
                kind: ConverterErrorKind::BadCcmConfiguration,
            });
        }
    }

    if let Some(d) = &request.converter_options.dsm_configuration {
        if url::Url::parse(&d.dsm_url).is_err() {
            return Err(ConverterError {
                message: "DsmConfiguration:dsm_url is not a valid url".to_string(),
                kind: ConverterErrorKind::BadDsmConfiguration,
            });
        }
    }

    Ok(())
}

fn create_user_program_config(
    converter_options: &ConverterOptions,
    input_image: &ImageWithDetails<'_>,
) -> Result<UserProgramConfig> {
    if !converter_options.entry_point.is_empty() {
        let (user, group) = input_image.user_and_group();

        Ok(UserProgramConfig {
            entry_point: converter_options.entry_point.join(" "),
            arguments: converter_options.entry_point_args.clone(),
            working_dir: input_image.working_dir(),
            user,
            group,
        })
    } else {
        input_image.create_user_program_config()
    }
}

async fn push_result_image(
    image: &ImageWithDetails<'_>,
    destination_auth: &Option<AuthConfig>,
) -> Result<()> {
    let result_repository = DockerDaemon::new(destination_auth);

    let image_reference = image.reference.to_string();

    info!("Pushing resulting image to {}!", image_reference);

    result_repository
        .push_image(image)
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::ImagePush,
        })?;

    info!(
        "Resulting image has been successfully pushed to {} !",
        image_reference
    );

    Ok(())
}

fn hex_response(arg: &str) -> Result<HexString> {
    HexString::from_str(arg).map_err(|err| ConverterError {
        message: format!("Failed converting string {} to hex string. {:?}", arg, err),
        kind: ConverterErrorKind::InternalError,
    })
}

async fn get_enclave_base_image<'a>(
    image: &'a mut Option<String>,
    image_path: String,
) -> Result<ImageWithDetails<'a>> {
    let username = env_var_or_none("ENCLAVE_IMAGE_USERNAME");
    let password = env_var_or_none("ENCLAVE_IMAGE_PASSWORD");

    get_base_image(image, image_path, username, password).await
}

async fn get_parent_base_image(image: &mut Option<String>) -> Result<()> {
    let username = env_var_or_none("PARENT_IMAGE_USERNAME");
    let password = env_var_or_none("PARENT_IMAGE_PASSWORD");

    let _ = get_base_image(image, PARENT_IMAGE_PATH.to_owned(), username, password).await?;

    Ok(())
}

async fn get_base_image<'a>(
    image: &'a mut Option<String>,
    base_image_tar_path: String,
    username: Option<String>,
    password: Option<String>,
) -> Result<ImageWithDetails<'a>> {
    let auth_config = match (username, password) {
        (Some(username), Some(password)) => Some(AuthConfig { username, password }),
        _ => None,
    };

    let repository = DockerDaemon::new(&auth_config);

    // If the environment variable is set, try loading it instead
    if let Some(image_name) = image {
        let reference = DockerReference::from_str(image_name).map_err(|err| ConverterError {
            message: format!(
                "Requisite image {} address has bad format. {:?}",
                image_name, err
            ),
            kind: ConverterErrorKind::BadRequest,
        })?;

        return match repository.get_local_image_details(&reference).await {
            Ok(details) => Ok(ImageWithDetails { reference, details }),
            Err(err) => Err(ConverterError {
                message: format!(
                    "Requisite image {} cannot be retrieved. {:?}",
                    image_name, err
                ),
                kind: ConverterErrorKind::BadRequest,
            }),
        };
    } else {
        *image = Some(
            repository
                .load_image(&base_image_tar_path)
                .await
                .map_err(|message| ConverterError {
                    message: format!(
                        "Failed to load requisite {} image. {:?}",
                        base_image_tar_path, message
                    ),
                    kind: ConverterErrorKind::DockerLoad,
                })?,
        );

        let loaded_image_name = image.as_ref().unwrap();

        info!(
            "Loaded requisite from backup tar file: {}",
            loaded_image_name
        );

        let reference =
            DockerReference::from_str(loaded_image_name).map_err(|err| ConverterError {
                message: format!(
                    "Requisite image {} address has bad format. {:?}",
                    loaded_image_name, err
                ),
                kind: ConverterErrorKind::BadRequest,
            })?;

        let details = match repository.get_local_image_details(&reference).await {
            Ok(details) => details,
            Err(message) => {
                info!(
                    "Failed retrieving requisite {} image from local repository. {:?}",
                    loaded_image_name, message
                );

                return Err(ConverterError {
                    message: format!(
                        "Failed retrieving requisite {} image. {:?}",
                        loaded_image_name, message
                    ),
                    kind: ConverterErrorKind::ImageGet,
                });
            }
        };

        Ok(ImageWithDetails { reference, details })
    }
}

fn env_var_or_none(var_name: &str) -> Option<String> {
    match env::var(var_name) {
        Ok(e) => Some(e),
        Err(err) => {
            warn!("Env var {} is not set. {:?}", var_name, err);
            None
        }
    }
}

fn preserve_images_list() -> Result<HashSet<ImageKind>> {
    let mut result: HashSet<ImageKind> = HashSet::new();

    if let Some(raw_list) = env_var_or_none("PRESERVE_IMAGES") {
        for e in raw_list.split(",") {
            let image_type = ImageKind::from_str(e).map_err(|err| ConverterError {
                message: format!("PRESERVE_IMAGES list contains incorrect item. {:?}", err),
                kind: ConverterErrorKind::BadRequest,
            })?;

            result.insert(image_type);
        }
    }

    Ok(result)
}

async fn clean_docker_images(
    docker: Docker,
    images_receiver: mpsc::Receiver<ImageToClean>,
    preserve: HashSet<ImageKind>,
) -> Result<()> {
    let mut received_images: Vec<ImageToClean> = Vec::new();

    // this loop will exit after all receivers have exited from
    // the image convert function irregardless if the function
    // exited normally or panicked.
    while let Ok(image) = images_receiver.recv() {
        if !preserve.contains(&image.kind) {
            received_images.push(image)
        }
    }

    for image in received_images {
        let image_interface = Image::new(&docker, image.name.clone());
        let mut delete_options = DeleteOptions::builder().force();

        match image_interface
            .delete_with_options(&delete_options.build())
            .await
        {
            Ok(_) => {
                info!("Successfully cleaned {:?} image {}", image.kind, image.name);
            }
            Err(e) => {
                warn!(
                    "Error cleaning {:?} image {}. {:?}",
                    image.kind, image.name, e
                );
            }
        }
    }

    Ok(())
}

pub(crate) async fn run_subprocess<S: AsRef<OsStr> + Debug, A: AsRef<OsStr> + Debug>(
    subprocess_path: S,
    args: &[A],
) -> std::result::Result<String, String> {
    let mut command = Command::new(&subprocess_path);

    command.stdout(Stdio::piped());
    command.args(args);

    debug!("Running subprocess {:?} {:?}", subprocess_path, args);
    let process = command.spawn().map_err(|err| {
        format!(
            "Failed to run subprocess {:?}. {:?}. Args {:?}",
            subprocess_path, err, args
        )
    })?;

    let output = process.output().await.map_err(|err| {
        format!(
            "Error while waiting for subprocess {:?} to finish: {:?}. Args {:?}",
            subprocess_path, err, args
        )
    })?;

    if !output.status.success() {
        let result = String::from_utf8_lossy(&output.stderr);

        error!("status: {}", output.status);
        error!("stderr: {}", result);

        Err(format!(
            "External process {:?} exited with {}. Stderr: {}",
            subprocess_path, output.status, result
        ))
    } else {
        let result = String::from_utf8_lossy(&output.stdout);

        info!("status: {}", output.status);
        info!("stdout: {}", result);

        Ok(result.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use api_model::converter::{
        CaCertificateConfig, CcmConfiguration, CertIssuer, CertificateConfig, ConversionRequest,
        ConversionRequestImageInfo, ConverterOptions, DsmConfiguration, KeyType,
    };
    use lazy_static::lazy_static;
    use serde_json::Value;

    use crate::{preserve_images_list, validate_request, ConverterErrorKind, ImageKind};

    lazy_static! {
        static ref SAMPLE_REQUEST: ConversionRequest = ConversionRequest {
            input_image: ConversionRequestImageInfo {
                name: "input-image".to_string(),
                auth_config: None
            },
            output_image: ConversionRequestImageInfo {
                name: "output-image".to_string(),
                auth_config: None
            },
            converter_options: ConverterOptions {
                allow_cmdline_args: None,
                allow_docker_pull_failure: None,
                app: None,
                ca_certificates: vec![],
                certificates: vec![CertificateConfig {
                    issuer: CertIssuer::ManagerCa,
                    subject: None,
                    alt_names: vec![],
                    key_type: KeyType::Rsa,
                    key_param: Some(Value::from(2048)),
                    key_path: None,
                    cert_path: None,
                    chain_path: None,
                }],
                debug: None,
                entry_point: vec![],
                entry_point_args: vec![],
                push_converted_image: None,
                env_vars: vec![],
                java_mode: None,
                enable_overlay_filesystem_persistence: None,
                ccm_configuration: None,
                dsm_configuration: None,
            },
        };
    }

    #[test]
    fn preserve_image_list_correct_pass() -> () {
        env::remove_var("PRESERVE_IMAGES");

        let mut result = preserve_images_list();

        assert!(result.is_ok());
        assert!(result
            .unwrap()
            .into_iter()
            .collect::<Vec<ImageKind>>()
            .is_empty());

        env::set_var("PRESERVE_IMAGES", "result");

        result = preserve_images_list();

        assert!(result.is_ok());
        assert_eq!(
            vec![ImageKind::Result],
            result.unwrap().into_iter().collect::<Vec<ImageKind>>()
        );

        env::set_var("PRESERVE_IMAGES", "reSuLt, inTermediaTe, INPUT");

        result = preserve_images_list();

        assert!(result.is_ok());
        {
            let mut left = vec![ImageKind::Result, ImageKind::Intermediate, ImageKind::Input];
            left.sort();

            let mut right = result.unwrap().into_iter().collect::<Vec<ImageKind>>();
            right.sort();

            assert_eq!(left, right);
        }
    }

    #[test]
    fn validate_converter_request_same_input_output_image_name() -> () {
        let request = ConversionRequest {
            input_image: ConversionRequestImageInfo {
                name: "sample-image".to_string(),
                auth_config: None,
            },
            output_image: ConversionRequestImageInfo {
                name: "sample-image".to_string(),
                auth_config: None,
            },
            converter_options: ConverterOptions {
                allow_cmdline_args: None,
                allow_docker_pull_failure: None,
                app: None,
                ca_certificates: vec![],
                certificates: vec![],
                debug: None,
                entry_point: vec![],
                entry_point_args: vec![],
                push_converted_image: None,
                env_vars: vec![],
                java_mode: None,
                enable_overlay_filesystem_persistence: None,
                ccm_configuration: None,
                dsm_configuration: None,
            },
        };
        let res = validate_request(&request);
        assert!(res.is_err());

        let converter_error = res.expect_err("");
        assert!(converter_error
            .message
            .contains("Input and output images must be different"));
        assert!(converter_error.kind == ConverterErrorKind::BadRequest);
    }

    #[test]
    fn validate_converter_request_correct_key_param() -> () {
        let request = ConversionRequest {
            input_image: ConversionRequestImageInfo {
                name: "input-image".to_string(),
                auth_config: None,
            },
            output_image: ConversionRequestImageInfo {
                name: "output-image".to_string(),
                auth_config: None,
            },
            converter_options: ConverterOptions {
                allow_cmdline_args: None,
                allow_docker_pull_failure: None,
                app: None,
                ca_certificates: vec![],
                certificates: vec![CertificateConfig {
                    issuer: CertIssuer::ManagerCa,
                    subject: None,
                    alt_names: vec![],
                    key_type: KeyType::Rsa,
                    key_param: Some(Value::from(2048)),
                    key_path: None,
                    cert_path: None,
                    chain_path: None,
                }],
                debug: None,
                entry_point: vec![],
                entry_point_args: vec![],
                push_converted_image: None,
                env_vars: vec![],
                java_mode: None,
                enable_overlay_filesystem_persistence: None,
                ccm_configuration: None,
                dsm_configuration: None,
            },
        };
        let res = validate_request(&request);
        assert!(res.is_ok());
    }

    #[test]
    fn validate_converter_request_incorrect_key_param() -> () {
        let request = ConversionRequest {
            input_image: ConversionRequestImageInfo {
                name: "input-image".to_string(),
                auth_config: None,
            },
            output_image: ConversionRequestImageInfo {
                name: "output-image".to_string(),
                auth_config: None,
            },
            converter_options: ConverterOptions {
                allow_cmdline_args: None,
                allow_docker_pull_failure: None,
                app: None,
                ca_certificates: vec![],
                certificates: vec![CertificateConfig {
                    issuer: CertIssuer::ManagerCa,
                    subject: None,
                    alt_names: vec![],
                    key_type: KeyType::Rsa,
                    key_param: Some(Value::from(1024)),
                    key_path: None,
                    cert_path: None,
                    chain_path: None,
                }],
                debug: None,
                entry_point: vec![],
                entry_point_args: vec![],
                push_converted_image: None,
                env_vars: vec![],
                java_mode: None,
                enable_overlay_filesystem_persistence: None,
                ccm_configuration: None,
                dsm_configuration: None,
            },
        };
        let res = validate_request(&request);
        assert!(res.is_err());

        let converter_error = res.expect_err("");
        assert!(converter_error
            .message
            .contains("Key param 1024 of certificate is not supported"));
        assert!(converter_error.kind == ConverterErrorKind::BadCertConfig);
    }

    #[test]
    fn validate_converter_request_unsupported_chain_path() -> () {
        let request = ConversionRequest {
            input_image: ConversionRequestImageInfo {
                name: "input-image".to_string(),
                auth_config: None,
            },
            output_image: ConversionRequestImageInfo {
                name: "output-image".to_string(),
                auth_config: None,
            },
            converter_options: ConverterOptions {
                allow_cmdline_args: None,
                allow_docker_pull_failure: None,
                app: None,
                ca_certificates: vec![],
                certificates: vec![CertificateConfig {
                    issuer: CertIssuer::ManagerCa,
                    subject: None,
                    alt_names: vec![],
                    key_type: KeyType::Rsa,
                    key_param: Some(Value::from(2048)),
                    key_path: None,
                    cert_path: None,
                    chain_path: Some("/tmp/capath".to_string()),
                }],
                debug: None,
                entry_point: vec![],
                entry_point_args: vec![],
                push_converted_image: None,
                env_vars: vec![],
                java_mode: None,
                enable_overlay_filesystem_persistence: None,
                ccm_configuration: None,
                dsm_configuration: None,
            },
        };
        let res = validate_request(&request);
        assert!(res.is_err());

        let converter_error = res.expect_err("");
        assert!(converter_error
            .message
            .contains("Chain path is not supported on this platform yet"));
        assert!(converter_error.kind == ConverterErrorKind::BadCertConfig);
    }

    #[test]
    fn validate_converter_request_unsupported_ca_certificates() -> () {
        let mut request = SAMPLE_REQUEST.clone();
        request.converter_options.ca_certificates = vec![CaCertificateConfig {
            ca_path: None,
            ca_cert: None,
            system: None,
        }];
        let res = validate_request(&request);
        assert!(res.is_err());

        let converter_error = res.expect_err("");
        assert!(converter_error
            .message
            .contains("CA certificates are not supported on this platform yet"));
        assert_eq!(converter_error.kind, ConverterErrorKind::BadCertConfig);
    }

    #[test]
    fn validate_converter_request_ccm_configuration() -> () {
        let mut request = SAMPLE_REQUEST.clone();

        // Test 1 - Default config i.e. No ccm config set
        assert!(validate_request(&request).is_ok());

        // Test 2 - Invalid CCM configuration set
        request.converter_options.ccm_configuration = Some(CcmConfiguration {
            ccm_url: "InvalidUrl".to_string(),
        });
        let res = validate_request(&request);
        assert!(res.is_err());

        let converter_error = res.expect_err("");
        assert_eq!(
            converter_error.message,
            "CcmConfiguration:ccm_url should be in <host>:<port> format"
        );
        assert_eq!(
            converter_error.kind,
            ConverterErrorKind::BadCcmConfiguration
        );

        // Test 3 - Valid CCM configuration set
        request.converter_options.ccm_configuration = Some(CcmConfiguration {
            ccm_url: "ccm.sample.fortanix.com:267".to_string(),
        });
        assert!(validate_request(&request).is_ok());
    }

    #[test]
    fn validate_converter_request_dsm_configuration() -> () {
        let mut request = SAMPLE_REQUEST.clone();

        // Test 1 - Default config i.e. No dsm config set
        assert!(validate_request(&request).is_ok());

        // Test 2 - Invalid DSM configuration set
        request.converter_options.dsm_configuration = Some(DsmConfiguration {
            dsm_url: "InvalidUrl".to_string(),
        });
        let res = validate_request(&request);
        assert!(res.is_err());

        let converter_error = res.expect_err("");
        assert_eq!(
            converter_error.message,
            "DsmConfiguration:dsm_url is not a valid url"
        );
        assert_eq!(
            converter_error.kind,
            ConverterErrorKind::BadDsmConfiguration
        );

        // Test 3 - Valid DSM configuration set
        request.converter_options.dsm_configuration = Some(DsmConfiguration {
            dsm_url: "https://someregion.smartkey.io".to_string(),
        });
        assert!(validate_request(&request).is_ok());
    }
}

lazy_static! {
    pub static ref SALMIAC_TEMP_DIR: String =
        env::var("SALMIAC_TEMP_DIR").unwrap_or("/tmp".to_string());
}
