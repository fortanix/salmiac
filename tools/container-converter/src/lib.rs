pub mod util;

use log::{debug, error, info};
use shiplift::{Image};
use shiplift::{Docker};
use shiplift::rep::{ImageDetails};
use std::process;
use std::env;

pub fn create_nitro_image(image_name : &str, output_file : &str) -> Result<(), String> {
    let nitro_cli_args = [
        "build-enclave",
        "--docker-uri",
        image_name,
        "--output-file",
        output_file
    ];

    let nitro_cli_command = process::Command::new("nitro-cli")
        .args(&nitro_cli_args)
        .output()
        .map_err(|err| format!("Failed to execute nitro-cli {:?}", err));

    nitro_cli_command.map(|output| {
        info!("status: {}", output.status);
        info!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        info!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    })
}

pub fn process_output(output : process::Output) -> Result<(), String> {
    log_output(&output);

    if !output.status.success() {
        Err(format!("Process exited with code {:?}", output.status.code()))
    }
    else {
        Ok(())
    }
}

fn log_output(output : &process::Output) -> () {
    info!("status: {}", output.status);
    info!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    info!("stderr: {}", String::from_utf8_lossy(&output.stderr));
}

pub struct DockerUtil {
    docker: Docker,
    image_name: String,
}

pub struct ImageWithDetails<'a> {
    pub image : Image<'a>,
    pub details : ImageDetails
}

impl DockerUtil {
    pub fn new(docker_image: String) -> Self {
        let docker = Docker::new();//Docker::unix("/var/run/docker.sock");

        let mut docker_image = docker_image;

        if !docker_image.contains(':') {
            docker_image.push_str(":latest");
        }

        DockerUtil {
            docker,
            image_name: docker_image,
        }
    }

    pub async fn local_image(&self) -> Option<ImageWithDetails<'_>> {
        let image = self.docker.images().get(&self.image_name);

        match image.inspect().await {
            Ok(details) => {
                Some(ImageWithDetails {
                    image,
                    details,
                })
            }
            Err(_) => {
                None
            }
        }
    }

    pub fn create_image(&self, docker_file: &str, image_tag: &str) -> Result<(), String> {
        env::set_var("DOCKER_BUILDKIT", "1");

        let args = [
            "build",
            "-t",
            image_tag,
            docker_file,
        ];

        let docker = process::Command::new("docker")
            .args(&args)
            .output()
            .map_err(|err| format!("Failed to run docker {:?}", err));

        docker.and_then(|output| {
            process_output(output)
        })
    }
}