use clap::{
    App,
    AppSettings,
    Arg,
    ArgMatches
};
use env_logger;
use log::{info};
use tempfile::TempDir;

use container_converter::{
    ParentImageBuilder,
    EnclaveImageBuilder
};
use container_converter::image::DockerUtil;

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let console_arguments = console_arguments();

    let client_image = {
        let mut arg = string_argument(&console_arguments, "image");

        if !arg.contains(':') {
            arg.push_str(":latest")
        };
        arg
    };

    let parent_image = string_argument_or_default(&console_arguments, "parent-image", "parent-base".to_string());

    let output_image = console_arguments.value_of("output-image")
        .unwrap_or(&(client_image.clone() + "-parent"))
        .to_string();

    let username = string_argument(&console_arguments, "pull-username");
    let password = string_argument(&console_arguments, "pull-password");

    let push_username = string_argument_or_default(&console_arguments, "push-username", username.clone());
    let push_password = string_argument_or_default(&console_arguments, "push-password", password.clone());

    let input_repository = DockerUtil::new(username, password);

    info!("Retrieving client image!");

    let input_image = input_repository.get_remote_image(&client_image).await.expect("Image not found");

    info!("Retrieving CMD from client image!");
    let client_cmd = input_image.details.config.cmd.expect("No CMD present in user image");

    info!("Creating working directory!");
    let temp_dir = TempDir::new().map_err(|err| format!("Cannot create temp dir {:?}", err))?;

    let enclave_builder = EnclaveImageBuilder {
        client_image: client_image.clone(),
        client_cmd : client_cmd[2..].to_vec(),
        dir : &temp_dir,
    };

    info!("Building enclave image!");
    enclave_builder.create_image(&input_repository)?;

    let parent_builder = ParentImageBuilder {
        output_image : output_image.clone(),
        parent_image,
        nitro_file: enclave_builder.nitro_image_name(),
        dir : &temp_dir,
    };

    info!("Building parent image!");
    parent_builder.create_image(&input_repository)?;

    info!("Resulting image has been successfully created!");

    let result_image = input_repository.get_local_image(&parent_builder.output_image)
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

fn string_argument(matches : &ArgMatches, name : &str) -> String {
    matches.value_of(name)
        .map(|e| e.to_string())
        .expect(&format!("Argument {} should be supplied", name))
}

fn string_argument_or_default(matches : &ArgMatches, name : &str, default : String) -> String {
    matches.value_of(name)
        .map(|e| e.to_string())
        .unwrap_or(default)
}