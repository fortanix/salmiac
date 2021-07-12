use clap::{
    App,
    AppSettings,
    Arg,
    ArgMatches
};
use env_logger;
use log::{
    info,
};

use container_converter::{
    ParentImageBuilder,
    EnclaveImageBuilder
};
use container_converter::image::DockerUtil;
use container_converter::file::create_work_dir;

use std::env;
use std::process;
use tokio::runtime::Runtime;


fn main() -> Result<(), String> {
    env::set_var("RUST_LOG","debug");

    env_logger::init();

    // Create future runtime for async connection with the docker daemon
    let rt = Runtime::new().unwrap();

    //let console_arguments = console_arguments();

    let client_image = "ubuntu:18.04";//console_arguments.value_of("image").expect("Image argument must be supplied");
    let docker_util = DockerUtil::new(client_image.to_string());

    // get image from local repo or remote
    info!("Retrieving client image!");

    let image_result = rt.block_on(docker_util.local_image());
    let image = image_result.expect(format!("Image {} not found in local repository", client_image).as_str());

    // get client CMD
    info!("Retrieving CMD from client image!");
    let client_cmd = image.details.config.cmd.expect("No CMD present in user image");

    info!("Creating working directory!");
    let tmp_dir = create_work_dir("tmp")?;

    let enclave_builder = EnclaveImageBuilder {
        client_image: client_image.to_string(),
        client_cmd,
        dir: &tmp_dir,
    };

    info!("Building enclave image!");
    enclave_builder.create_image(&docker_util, rt)?;

    let parent_builder = ParentImageBuilder {
        client_image: client_image.to_string(),
        nitro_file: enclave_builder.nitro_image_name(),
        dir: &tmp_dir,
    };

    info!("Building parent image!");
    parent_builder.create_image(&docker_util)?;

    info!("Resulting image has been successfully created!");
    process::exit(0);
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
        .get_matches()
}