use tempfile::TempDir;
use log::info;
use clap::ArgMatches;
use serde::Deserialize;
use docker_image_reference::Reference as DockerReference;

use crate::image::DockerUtil;
use crate::image_builder::{EnclaveImageBuilder, ParentImageBuilder};

pub mod image;
pub mod file;
pub mod image_builder;

pub type Result<T> = std::result::Result<T, ConverterError>;

#[derive(Deserialize, Clone, Debug)]
pub struct ConverterArgs {
    pub pull_repository : Repository,

    pub push_repository : Repository,

    pub parent_image : String,
}

impl ConverterArgs {
    pub fn from_console_arguments(console_arguments : &ArgMatches) -> std::result::Result<ConverterArgs, String> {
        let client_image = console_argument::<String>(console_arguments, "image");
        let parent_image = console_argument_or_default::<String>(
            console_arguments,
            "parent-image",
            "parent-base".to_string());
        let output_image = console_argument::<String>(console_arguments, "output-image");

        if client_image == output_image {
            return Err("Client and output image should point to different images!".to_string())
        }

        let pull_username = console_argument::<String>(console_arguments, "pull-username");
        let pull_password = console_argument::<String>(console_arguments, "pull-password");

        let push_username = console_argument_or_default::<String>(
            console_arguments,
            "push-username",
            pull_username.clone());
        let push_password = console_argument_or_default::<String>(
            console_arguments,
            "push-password",
            pull_password.clone());

        Ok(ConverterArgs {
            pull_repository: Repository {
                image: client_image,
                credentials: Credentials {
                    username: pull_username,
                    password: pull_password
                }
            },
            push_repository: Repository {
                image: output_image,
                credentials: Credentials {
                    username: push_username,
                    password: push_password
                }
            },
            parent_image
        })
    }
}

#[derive(Deserialize, Clone, Debug)]
pub struct Repository {
    pub image : String,

    pub credentials : Credentials
}

impl Repository {
    fn image_reference(&self) -> DockerReference {
        DockerReference::from_str(&self.image).unwrap()
    }
}


#[derive(Deserialize, Clone, Debug)]
pub struct Credentials {
    pub username : String,

    pub password : String
}

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
    ParentImageCreation
}

pub async fn run(args: ConverterArgs) -> Result<String> {
    let input_repository = DockerUtil::new(&args.pull_repository.credentials);

    info!("Retrieving client image!");
    let input_image = input_repository.get_remote_image(&args.pull_repository.image_reference())
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::ImagePull
        })?;

    info!("Retrieving CMD from client image!");
    let client_cmd = input_image.details.config.cmd.expect("No CMD present in user image");

    info!("Creating working directory!");
    let temp_dir = TempDir::new().map_err(|err| ConverterError {
        message: format!("Cannot create temp dir {:?}", err),
        kind: ConverterErrorKind::RequisitesCreation
    })?;

    let enclave_builder = EnclaveImageBuilder {
        client_image: args.pull_repository.image.clone(),
        client_cmd : client_cmd[2..].to_vec(), // removes /bin/sh -c
        dir : &temp_dir,
    };

    info!("Building enclave image!");
    let nitro_image_result = enclave_builder.create_image(&input_repository)?;

    let parent_builder = ParentImageBuilder {
        output_image : args.push_repository.image.clone(),
        parent_image : args.parent_image.clone(),
        nitro_file : nitro_image_result.nitro_file,
        dir : &temp_dir,
    };

    info!("Building parent image!");
    parent_builder.create_image(&input_repository)?;

    info!("Resulting image has been successfully created!");

    let result_image = input_repository.get_local_image(&args.push_repository.image_reference())
        .await
        .expect("Failed to retrieve converted image");

    let result_repository = DockerUtil::new(&args.push_repository.credentials);

    info!("Pushing resulting image to {}!", args.push_repository.image);
    result_repository.push_image(&result_image, &args.push_repository.image_reference())
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::ImagePush
        })?;

    info!("Resulting image has been successfully pushed to {} !", args.push_repository.image);

    Ok(nitro_image_result.measurements)
}


fn console_argument<'a, T : From<&'a str>>(matches : &'a ArgMatches, name : &str) -> T {
    matches.value_of(name)
        .map(|e| T::from(e))
        .expect(&format!("Argument {} should be supplied", name))
}

fn console_argument_or_default<'a, T : From<&'a str>>(matches : &'a ArgMatches, name : &str, default : T) -> T {
    matches.value_of(name)
        .map(|e| T::from(e))
        .unwrap_or(default)
}
