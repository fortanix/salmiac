use clap::{
    App,
    AppSettings,
    Arg,
    ArgMatches
};
use env_logger;
use log::{info};
use tempfile::TempDir;
use serde::Deserialize;
use docker_image_reference::Reference as DockerReference;

use container_converter::{ParentImageBuilder, EnclaveImageBuilder};
use container_converter::image::DockerUtil;

use std::fs;

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let console_arguments = console_arguments();

    let client_image_raw = console_argument::<String>(&console_arguments, "image");
    let parent_image = console_argument_or_default::<String>(
        &console_arguments,
        "parent-image",
        "parent-base".to_string());
    let output_image_raw = console_argument::<String>(&console_arguments, "output-image");

    if client_image_raw == output_image_raw {
        return Err("Client and output image should point to different images!".to_string())
    }

    let client_image = DockerReference::from_str(&client_image_raw)
        .expect("Incorrect image format");
    let output_image = DockerReference::from_str(&output_image_raw)
        .expect("Incorrect output-image format");

    let credentials = if console_arguments.is_present("credentials-file") {
        let path = console_argument::<String>(&console_arguments, "credentials-file");
        let file_contents = fs::read_to_string(path)
            .map_err(|err| format!("Failed to read credentials file: {:?}", err))?;

        toml::from_str::<Credentials>(&file_contents)
            .map_err(|err| format!("Failed to read credentials from file: {:?}", err))?
    } else {
        Credentials::from_console_args(&console_arguments)
    };

    let input_repository = DockerUtil::new(credentials.pull_username, credentials.pull_password);

    info!("Retrieving client image!");
    let input_image = input_repository.get_remote_image(&client_image)
        .await
        .expect(&format!("Image {} not found", client_image_raw));

    info!("Retrieving CMD from client image!");
    let client_cmd = input_image.details.config.cmd.expect("No CMD present in user image");

    info!("Creating working directory!");
    let temp_dir = TempDir::new().map_err(|err| format!("Cannot create temp dir {:?}", err))?;

    let enclave_builder = EnclaveImageBuilder {
        client_image: client_image_raw.clone(),
        client_cmd : client_cmd[2..].to_vec(), // removes /bin/sh -c
        dir : &temp_dir,
    };

    info!("Building enclave image!");
    let nitro_file = enclave_builder.create_image(&input_repository)?;

    let parent_builder = ParentImageBuilder {
        output_image : output_image_raw.clone(),
        parent_image,
        nitro_file,
        dir : &temp_dir,
    };

    info!("Building parent image!");
    parent_builder.create_image(&input_repository)?;

    info!("Resulting image has been successfully created!");

    let result_image = input_repository.get_local_image(&output_image)
        .await
        .expect("Failed to retrieve converted image");

    let result_repository = DockerUtil::new(credentials.push_username, credentials.push_password);

    info!("Pushing resulting image to {}!", output_image_raw);
    result_repository.push_image(&result_image, &output_image).await?;

    info!("Resulting image has been successfully pushed to {} !", output_image_raw);

    Ok(())
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Container converter")
        .about("Converts user docker container to be able to run in AWS Nitro environment")
        .setting(AppSettings::DisableVersion)
        .arg(
            Arg::with_name("image")
                .help("your docker image")
                .long("image")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("parent-image")
                .help("parent image")
                .long("parent-image")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("output-image")
                .help("output image name")
                .long("output-image")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("pull-username")
                .help("user name for a repository that contains input image")
                .long("pull-username")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("pull-password")
                .help("password for a repository that contains input image")
                .long("pull-password")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("push-username")
                .help("user name for a repository that will contain output image")
                .long("push-username")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("push-password")
                .help("password for a repository that will contain output image")
                .long("push-password")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("credentials-file")
                .help("Path to a file with credentials")
                .long("credentials-file")
                .takes_value(true)
                .required(false),
        )
        .get_matches()
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

#[derive(Deserialize, Debug)]
struct Credentials {
    pub pull_username : String,

    pub pull_password : String,

    pub push_username : String,

    pub push_password : String
}

impl Credentials {
    pub fn from_console_args(console_arguments : &ArgMatches) -> Self {
        let pull_username = console_argument::<String>(&console_arguments, "pull-username");
        let pull_password = console_argument::<String>(&console_arguments, "pull-password");

        let push_username = console_argument_or_default::<String>(
            &console_arguments,
            "push-username",
            pull_username.clone());
        let push_password = console_argument_or_default::<String>(
            &console_arguments,
            "push-password",
            pull_password.clone());

        Credentials {
            pull_username,
            pull_password,
            push_username,
            push_password
        }
    }
}