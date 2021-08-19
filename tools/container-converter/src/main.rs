use clap::{
    App,
    AppSettings,
    Arg,
    ArgMatches
};
use env_logger;
use log::{info};
use async_std::task;
use container_converter::{
    ParentImageBuilder,
    EnclaveImageBuilder,
    global_resources
};
use container_converter::image::DockerUtil;
use container_converter::file::create_work_dir;

use std::env;

fn main() -> Result<(), String> {
    env::set_var("RUST_LOG","debug");

    env_logger::init();

    let console_arguments = console_arguments();

    let client_image = console_arguments.value_of("image").expect("Image argument must be supplied").to_string();
    let parent_image = console_arguments.value_of("parent-image").unwrap_or("parent-base").to_string();
    let output_image = console_arguments.value_of("output-image").unwrap_or(&*(client_image.clone() + "-parent")).to_string();

    let docker_util = DockerUtil::new(client_image.clone());

    info!("Retrieving client image!");

    let image_result = task::block_on(docker_util.local_image());
    let image = image_result.expect(format!("Image {} not found in local repository", &client_image).as_str());

    info!("Retrieving CMD from client image!");
    let client_cmd = image.details.config.cmd.expect("No CMD present in user image");

    info!("Creating working directory!");
    let global_resources = global_resources();
    let temp_dir = create_work_dir(&global_resources)?;

    let enclave_builder = EnclaveImageBuilder {
        client_image: client_image.clone(),
        client_cmd,
        dir : &temp_dir,
    };

    info!("Building enclave image!");
    enclave_builder.create_image(&docker_util)?;

    let parent_builder = ParentImageBuilder {
        output_image,
        parent_image,
        nitro_file: enclave_builder.nitro_image_name(),
        dir : &temp_dir,
    };

    info!("Building parent image!");
    parent_builder.create_image(&docker_util)?;

    info!("Resulting image has been successfully created!");

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
        .get_matches()
}