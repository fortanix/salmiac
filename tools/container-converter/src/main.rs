use clap::{
    App,
    AppSettings,
    Arg,
    ArgMatches
};
use env_logger;
use log::{info};
use tempfile::TempDir;

use container_converter::{ParentImageBuilder, EnclaveImageBuilder};
use container_converter::image::DockerUtil;

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let console_arguments = console_arguments();

    let client_image = console_argument::<String>(&console_arguments, "image");
    let parent_image = console_argument_or_default::<String>(
        &console_arguments,
        "parent-image",
        "parent-base".to_string());
    let output_image = console_argument_or_default::<String>(
        &console_arguments,
        "output-image",
        client_image.clone());

    let username = console_argument::<String>(&console_arguments, "pull-username");
    let password = console_argument::<String>(&console_arguments, "pull-password");

    let push_username = console_argument_or_default::<String>(
        &console_arguments,
        "push-username",
        username.clone());
    let push_password = console_argument_or_default::<String>(
        &console_arguments,
        "push-password",
        password.clone());

    let input_repository = DockerUtil::new(username, password);

    info!("Retrieving client image!");
    let input_image = input_repository.get_remote_image(&client_image)
        .await
        .expect(&format!("Image {} not found", client_image));

    info!("Retrieving CMD from client image!");
    let client_cmd = input_image.details.config.cmd.expect("No CMD present in user image");

    info!("Creating working directory!");
    let temp_dir = TempDir::new().map_err(|err| format!("Cannot create temp dir {:?}", err))?;

    let enclave_builder = EnclaveImageBuilder {
        client_image: client_image.clone(),
        client_cmd : client_cmd[2..].to_vec(), // removes /bin/sh -c
        dir : &temp_dir,
    };

    info!("Building enclave image!");
    let nitro_file = enclave_builder.create_image(&input_repository)?;

    let parent_builder = ParentImageBuilder {
        output_image : output_image.clone(),
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

    let result_repository = DockerUtil::new(push_username, push_password);

    info!("Pushing resulting image to {}!", output_image);
    result_repository.push_image(&result_image, &output_image).await?;

    info!("Resulting image has been successfully pushed to {} !", output_image);

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
                .required(false),
        )
        .arg(
            Arg::with_name("pull-username")
                .help("user name for a repository that contains input image")
                .long("pull-username")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("pull-password")
                .help("password for a repository that contains input image")
                .long("pull-password")
                .takes_value(true)
                .required(true),
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