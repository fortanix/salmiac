use clap::{
    App,
    AppSettings,
    Arg,
    SubCommand,
    ArgMatches
};
use env_logger;
use log::{
    info,
    debug,
    error
};
use container_converter::DockerUtil;
use shiplift::Container;
use std::env;
use std::fs;
use std::process;
use std::io::Write;
use tokio::runtime::Runtime;


fn main() -> Result<(), String> {
    env::set_var("RUST_LOG","debug");

    env_logger::init();

    // Create the runtime
    let rt = Runtime::new().unwrap();

    //let console_arguments = console_arguments();

    let image_name = "ubuntu:18.04";//console_arguments.value_of("image").expect("Image argument must be supplied");
    let docker_util = DockerUtil::new(image_name.to_string());

    // get image from local repo or remote
    let image_result = rt.block_on(docker_util.local_image());
    let image = image_result.expect(format!("Image {} not found in local repository", image_name).as_str());
    let user_cmd = image.details.config.cmd.expect("No CMD present in user image");

    create_docker_file(image_name)?;
    append_user_cmd_to_startup(user_cmd)?;

    let new_image_name = image_name.to_string() + "-converted";
    let create_image_result = docker_util.create_image1("/home/nikitashyrei/salmiac/tools/container-converter/target/debug", &new_image_name)?;
    //let new_image = create_image_result?;

    let nitro_cli_args = [
        "build-enclave",
        "--docker-dir .",
        &format!("--docker-uri {}", new_image_name),
        &format!("--output-file {}.eif", new_image_name)
    ];

    let nitro_cli_command = process::Command::new("nitro-cli")
        .args(&nitro_cli_args)
        .output()
        .map_err(|err| format!("Failed to execute nitro-cli {:?}", err))?;

    // create container from image
    // let container = docker_util.container(&image).map_err(|err| format!("Failed to create docker container {:?}", err))?;
    // insert startup.sh and vsock-proxy binary into the image

    process::exit(0);
}

fn append_user_cmd_to_startup(user_cmd : Vec<String>) -> Result<(), String> {
    let mut startup_file = fs::OpenOptions::new()
        .append(true)
        .open("/home/nikitashyrei/salmiac/tools/container-converter/target/debug/startup.sh")
        .map_err(|err| format!("Failed to open startup.sh file {:?}", err))?;

    let cmd = user_cmd.join(" ");
    startup_file.write_all(cmd.as_bytes());

    Ok(())
}

fn create_docker_file(image_name : &str) -> Result<(), String> {
    let mut docker_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/home/nikitashyrei/salmiac/tools/container-converter/target/debug/Dockerfile")
        .map_err(|err| format!("Failed to create docker file {:?}", err))?;

    let from = format!("FROM {} \n", image_name);

    docker_file.write_all(from.as_bytes());

    let copy = format!("COPY {} {} ./\n", "startup.sh", "vsock-proxy");

    docker_file.write_all(copy.as_bytes());

    let cmd = format!("CMD {} \n", "./startup.sh");

    docker_file.write_all(cmd.as_bytes());

    Ok(())
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Container converter")
        .about("Converts user docker container to be able to run in AWS Nitro environment")
        .setting(AppSettings::DisableVersion)
        .arg(
            Arg::with_name("image")
                .help("your docker image")
                .takes_value(true)
                .required(true),
        )
        .get_matches()
}