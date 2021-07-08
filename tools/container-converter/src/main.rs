use clap::{
    App,
    AppSettings,
    Arg,
    ArgMatches
};
use env_logger;
use log::{
    info,
    debug,
    error
};
use container_converter::{
    DockerUtil,
    create_nitro_image
};
use container_converter::util::{
    RichFile,
    TempFile
};
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

    // get client CMD
    let user_cmd = image.details.config.cmd.expect("No CMD present in user image");

    fs::copy("resources/enclave/vsock-proxy", "vsock-proxy")
        .map_err(|err| format!("Failed to copy vsock-proxy bin {:?}", err))?;

    let nitro_file = create_enclave_image(image_name, user_cmd, &docker_util)?;

    create_parent_image(&image_name, &nitro_file, &docker_util)?;

    fs::remove_file("vsock-proxy").map_err(|err| format!("Failed to remove file {:?}", err))?;
    fs::remove_file(nitro_file).map_err(|err| format!("Failed to remove file {:?}", err))?;

    process::exit(0);
}

fn create_enclave_image(client_image : &str, client_cmd : Vec<String>, docker_util : &DockerUtil) -> Result<String, String> {
    let enclave_image_name = client_image.to_string() + "-enclave";
    let nitro_image_name = enclave_image_name.to_string() + ".eif";

    let docker_file = TempFile(create_enclave_docker_file(client_image)?);
    let startup_script = TempFile(create_enclave_startup_script(client_cmd)?);

    docker_util.create_image(".", &enclave_image_name)?;
    create_nitro_image(&enclave_image_name, &nitro_image_name)?;

    Ok(nitro_image_name)
}

fn create_parent_image(client_image : &str, nitro_file: &str, docker_util : &DockerUtil) -> Result<(), String> {
    let parent_image_name = client_image.to_string() + "-parent";

    let docker_file = TempFile(create_parent_docker_file(&parent_image_name, nitro_file)?);
    let startup_script = TempFile(create_parent_startup_script(nitro_file)?);

    docker_util.create_image(".", &parent_image_name)?;

    Ok(())
}

fn create_parent_startup_script(nitro_file: &str) -> Result<RichFile, String> {
    fs::copy("resources/parent/start-parent.sh", "start-parent.sh")
        .map_err(|err| format!("Failed to copy base startup script {:?}", err))?;

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open("start-parent.sh")
        .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

    let cmd = format!("nitro-cli run-enclave --eif-path {} --enclave-cid 4 --cpu-count 2 --memory 1124 --debug-mode", nitro_file);

    file.write_all(cmd.as_bytes());

    Ok(RichFile{
        file,
        path: "start-parent.sh"
    })
}

fn create_enclave_startup_script<'a>(user_cmd : Vec<String>) -> Result<RichFile<'a>, String> {
    fs::copy("resources/enclave/start-enclave.sh", "start-enclave.sh")
        .map_err(|err| format!("Failed to copy base startup script {:?}", err))?;

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open("start-enclave.sh")
        .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

    let cmd = user_cmd.join(" ");

    file.write_all(cmd.as_bytes());

    Ok(RichFile{
        file,
        path: "start-enclave.sh"
    })
}

fn create_enclave_docker_file<'a>(image_name : &str) -> Result<RichFile<'a>, String> {
    create_docker_file(image_name, "start-enclave.sh vsock-proxy", "./start-enclave.sh")
}

fn create_parent_docker_file<'a>(image_name : &str, nitro_file: &str) -> Result<RichFile<'a>, String> {
    let copy = nitro_file.to_string() + " start-parent.sh";

    create_docker_file(image_name, &copy, "./start-parent.sh")
}

fn create_docker_file<'a>(image_name : &str, copy : &str, cmd : &str) -> Result<RichFile<'a>, String> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("Dockerfile")
        .map_err(|err| format!("Failed to create docker file {:?}", err))?;

    let filled_contents = format!(
        "FROM {} \n\
         COPY {} ./ \n\
         CMD  {} \n",
         image_name,
         copy,
         cmd
    );

    file.write_all(filled_contents.as_bytes());

    Ok(RichFile{
        file,
        path: "Dockerfile"
    })
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