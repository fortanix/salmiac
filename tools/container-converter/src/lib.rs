use log::{debug, error, info};
use shiplift::{RegistryAuth, Image, Container, Containers, ContainerOptions};
use shiplift::{BuildOptions, Docker, PullOptions};
use shiplift::rep::{ContainerCreateInfo, ImageDetails};
use std::process;
use std::env;
use futures::executor;
use futures::StreamExt;

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

    pub fn create_image1(&self, docker_file: &str, image_tag: &str) -> Result<(), String> {
        env::set_var("DOCKER_BUILDKIT", "1");

        let args = [
            &format!("build {}", docker_file)
        ];

        let docker = process::Command::new("docker")
            .args(&args)
            .output()
            .map_err(|err| format!("Failed to run docker {:?}", err));

        docker.map(|output| {
            info!("status: {}", output.status);
            info!("stdout: {}", String::from_utf8_lossy(&output.stdout));
            info!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        })
    }

    pub async fn create_image(&self, docker_file: &str, image_tag: &str) -> Result<(), String> {
        let build_options = BuildOptions::builder(docker_file).tag(image_tag).build();

        let mut stream = self.docker.images().build(&build_options);

        let mut result: Result<(), String> = Ok(());

        while let Some(build_result) = stream.next().await {
            match build_result {
                Err(e) => {
                    result = Err(format!("Failed to create docker image {:?}", e))
                }
                Ok(progress) => {
                    info!("{:?}", progress)
                }
            }
        }
        result
    }

    pub fn container(&self, image : &str) -> shiplift::Result<ContainerCreateInfo> {
        let build_options = ContainerOptions::builder(image).build();

        let result = async {
            self.docker.containers()
                .create(&build_options)
                .await
        };

        executor::block_on(result)
    }
}