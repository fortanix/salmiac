use clap::{
    App,
    AppSettings,
    Arg,
    ArgMatches
};
use env_logger;
use log::{error};
use docker_image_reference::Reference as DockerReference;

use container_converter::ConverterArgs;

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let console_arguments = console_arguments();

    let converter_arguments = ConverterArgs::from_console_arguments(&console_arguments)
        .expect("Cannot create console arguments");

    container_converter::run(converter_arguments)
        .await
        .map(|measurements| println!("{}", measurements))
        .map_err(|err| {
            error!("Converter exited with error: {}", err.message);
            err.message
        })
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Container converter")
        .about("Converts user docker container to be able to run in AWS Nitro environment")
        .setting(AppSettings::DisableVersion)
        .arg(
            Arg::with_name("image")
                .help("your docker image")
                .long("image")
                .validator(image_validator)
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
                .validator(output_image_validator)
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

fn image_validator(arg : String) -> Result<(), String> {
    DockerReference::from_str(&arg)
        .map_err(|err| format!("Incorrect image format. {:?}", err))?;

    Ok(())
}

fn output_image_validator(arg : String) -> Result<(), String> {
    let output_image = DockerReference::from_str(&arg)
        .map_err(|err| format!("Incorrect image format. {:?}", err))?;

    if output_image.tag().is_none() || output_image.has_digest() {
        Err("Output image must have a tag and have no digest!".to_string())
    } else {
        Ok(())
    }
}