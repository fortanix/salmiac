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
use container_converter::util::{RichFile, TempRichFile, TempDir};
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


    let tmp_dir = create_work_dir();

    let nitro_file = create_enclave_image(image_name, user_cmd, &docker_util, rt)?;

    create_parent_image(&image_name, &nitro_file, &docker_util)?;

    fs::remove_file("vsock-proxy").map_err(|err| format!("Failed to remove file {:?}", err))?;
    fs::remove_file(nitro_file).map_err(|err| format!("Failed to remove file {:?}", err))?;

    process::exit(0);
}

fn create_enclave_image(client_image : &str, client_cmd : Vec<String>, docker_util : &DockerUtil, r : Runtime) -> Result<String, String> {
    let enclave_image_name = client_image.to_string() + "-enclave";
    let enclave_image_tar = enclave_image_name.to_string() + ".tar";
    let nitro_image_name = enclave_image_name.to_string() + ".eif";

    create_enclave_requisites("tmp", client_image, client_cmd);
//    let docker_file = TempRichFile(create_enclave_docker_file(client_image)?);
  //  let startup_script = TempRichFile(create_enclave_startup_script(client_cmd.clone())?);

    docker_util.create_image_buildkit(".", &enclave_image_name)?;
    let load_result = r.block_on(docker_util.load_image(&enclave_image_tar))?;
    create_nitro_image(&enclave_image_name, &nitro_image_name)?;

    Ok(nitro_image_name)
}

fn create_work_dir<'a>() -> Result<TempDir<'a>, String> {
    fs::create_dir("tmp").map_err(|err| format!("Cannot create dir"))?;

    fs::copy("resources/enclave/vsock-proxy", "tmp/vsock-proxy")
        .map_err(|err| format!("Failed to copy vsock-proxy bin {:?}", err))?;

    Ok(TempDir("tmp"))
}

fn create_enclave_requisites(dir : &str, client_image : &str, client_cmd : Vec<String>) -> Result<(), String> {
    create_enclave_docker_file(client_image)?;
    create_enclave_startup_script(client_cmd)?;

    Ok(())
}

fn create_parent_requisites(client_image : &str, nitro_file: &str) -> Result<(), String> {
    create_parent_docker_file(client_image, nitro_file)?;
    create_parent_startup_script(nitro_file)?;

    Ok(())
}

fn create_parent_image(client_image : &str, nitro_file : &str, docker_util : &DockerUtil) -> Result<(), String> {
    let parent_image_name = client_image.to_string() + "-parent";

    create_parent_requisites(client_image, nitro_file);

    docker_util.create_image_buildkit(".", &parent_image_name)?;

    Ok(())
}

fn create_parent_startup_script(nitro_file: &str) -> Result<(), String> {
    fs::copy("resources/parent/start-parent.sh", "tmp/start-parent.sh")
        .map_err(|err| format!("Failed to copy base startup script {:?}", err))?;

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open("tmp/start-parent.sh")
        .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

    let cmd = format!("nitro-cli run-enclave --eif-path {} --enclave-cid 4 --cpu-count 2 --memory 1124 --debug-mode", nitro_file);

    file.write_all(cmd.as_bytes());

    Ok(())
}

fn create_enclave_startup_script<'a>(user_cmd : Vec<String>) -> Result<(), String> {
    fs::copy("resources/enclave/start-enclave.sh", "tmp/start-enclave.sh")
        .map_err(|err| format!("Failed to copy base startup script {:?}", err))?;

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open("tmp/start-enclave.sh")
        .map_err(|err| format!("Failed to open enclave startup script {:?}", err))?;

    let cmd = user_cmd.join(" ");

    file.write_all(cmd.as_bytes());

    Ok(())
}

fn create_enclave_docker_file<'a>(image_name : &str) -> Result<(), String> {
    create_docker_file("tmp", image_name, "start-enclave.sh vsock-proxy", "./start-enclave.sh")
}

fn create_parent_docker_file<'a>(image_name : &str, nitro_file: &str) -> Result<(), String> {
    let copy = nitro_file.to_string() + " start-parent.sh";

    create_docker_file("tmp", image_name, &copy, "./start-parent.sh")
}

fn create_docker_file<'a>(path : &str, image_name : &str, copy : &str, cmd : &str) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{}/{}", path, "Dockerfile"))
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