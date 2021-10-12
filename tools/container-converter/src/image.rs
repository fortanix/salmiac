use log::{info, error};
use shiplift::{Docker, Image, RegistryAuth, PullOptions, TagOptions};
use shiplift::image::{PushOptions, ImageDetails};
use futures::StreamExt;
use docker_image_reference::Reference as DockerReference;

use std::process;
use std::env;
use std::fs;
use std::path::Path;
use crate::Credentials;

pub fn create_nitro_image(image_name : &str, output_file : &Path) -> Result<String, String> {
    let output = output_file.to_str().expect("Cannot convert nitro output path to string");

    let nitro_cli_args = [
        "build-enclave",
        "--docker-uri",
        image_name,
        "--output-file",
        output
    ];

    let nitro_cli_command = process::Command::new("nitro-cli")
        .args(&nitro_cli_args)
        .output()
        .map_err(|err| format!("Failed to execute nitro-cli {:?}", err));

    nitro_cli_command.and_then(|output| {
        process_output(output, "nitro-cli")
    })
}

fn process_output(output : process::Output, process_name : &str) -> Result<String, String> {
    if !output.status.success() {
        let result = String::from_utf8_lossy(&output.stderr);

        error!("status: {}", output.status);
        error!("stderr: {}", result);

        Err(format!("External process {} exited with {}. Stderr: {}", process_name, output.status, result))
    } else {
        let result = String::from_utf8_lossy(&output.stdout);

        info!("status: {}", output.status);
        info!("stdout: {}", result);

        Ok(result.to_string())
    }
}

pub struct DockerUtil {
    docker: Docker,
    credentials : RegistryAuth
}

pub struct ImageWithDetails<'a> {
    pub image : Image<'a>,
    pub details : ImageDetails
}

impl DockerUtil {
    pub fn new(credentials : &Credentials) -> Self {
        let docker = Docker::new();

        let credentials = RegistryAuth::builder()
            .username(&credentials.username)
            .password(&credentials.password)
            .build();

        DockerUtil {
            docker,
            credentials
        }
    }

    pub async fn get_remote_image(&self, image : &DockerReference<'_>) -> Result<ImageWithDetails<'_>, String> {
        self.pull_image(image).await?;

        Ok(self.get_local_image(image).await.expect("Failed to pull image"))
    }

    pub async fn get_local_image(&self, address : &DockerReference<'_>) -> Option<ImageWithDetails<'_>> {
        let image = self.docker.images().get(address.name());

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

    pub async fn load_image(&self, tar_path : &str) -> Result<(), String> {
        let tar = fs::File::open(tar_path).map_err(|err| format!("Unable to open file, {:?}", err))?;

        let reader = Box::from(tar);
        let mut stream = self.docker.images().import(reader);

        while let Some(import_result) = stream.next().await {
            match import_result {
                Ok(output) => {
                    info!("{:?}", output)
                },
                Err(e) => {
                    return Err(format!("{:?}", e));
                },
            }
        }

        Ok(())
    }

    pub async fn push_image(&self, image : &ImageWithDetails<'_>, address: &DockerReference<'_>) -> Result<(), String> {
        let repository = address.name();
        let mut tag_options = TagOptions::builder();
        tag_options.repo(repository);

        let mut push_options = PushOptions::builder();
        push_options.auth(self.credentials.clone());

        if let Some(tag_value) = address.tag() {
            tag_options.tag(tag_value);
            push_options.tag(tag_value.to_string());
        }

        image.image.tag(&tag_options.build())
            .await
            .map_err(|err| format!("Failed to tag image {} with repo {}. Err {:?}", image.details.id, address, err))?;

        self.docker.images()
            .push(repository, &push_options.build())
            .await
            .map_err(|err| format!("Failed to push image {} into repo {}. Err: {:?}", image.details.id, repository, err))
    }

    pub fn create_image(&self, docker_dir: &Path, image_tag: &str) -> Result<String, String> {
        env::set_var("DOCKER_BUILDKIT", "1");

        let dir = docker_dir.to_str().unwrap();

        let args = [
            "build",
            "-t",
            image_tag,
            dir,
        ];

        let docker = process::Command::new("/usr/bin/docker")
            .args(&args)
            .output()
            .map_err(|err| format!("Failed to run docker {:?}", err));

        docker.and_then(|output| {
            process_output(output, "docker")
        })
    }

    pub fn create_image_buildkit(&self, docker_dir: &str, image_tag: &str, output_file : &str) -> Result<String, String> {
        let user_id = 1000;
        let args = [
            "--addr",
            &format!("unix:///run/user/{}/buildkit/buildkitd.sock", user_id),
            "build",
            "--frontend",
            "dockerfile.v0",
            "--local",
            &format!("context={}", docker_dir),
            "--local",
            &format!("dockerfile={}", docker_dir),
            "--output",
            &format!("type=docker,name={},dest={}.tar", image_tag, output_file),
        ];

        let run_buildkit = process::Command::new("buildctl")
            .args(&args)
            .output()
            .map_err(|err| format!("Failed to run buildkit {:?}", err));

        run_buildkit.and_then(|output| {
            process_output(output, "docker")
        })
    }

    async fn pull_image(&self, address: &DockerReference<'_>) -> Result<(), String> {
        let pull_options = PullOptions::builder()
            .image(address.to_string())
            .auth(self.credentials.clone())
            .build();

        let mut stream = self.docker
            .images()
            .pull(&pull_options);

        while let Some(pull_result) = stream.next().await {
            match pull_result {
                Ok(output) => {
                    info!("{:?}", output)
                },
                Err(e) => {
                    return Err(format!("{}", e))
                }
            }
        }

        Ok(())
    }
}

trait DockerImageURL {
    fn repository_and_tag(&self) -> (&str, Option<&str>);
}

impl DockerImageURL for &str {
    fn repository_and_tag(&self) -> (&str, Option<&str>) {
        self.rfind(":")
            .map(|pos| (&self[..pos], Some(&self[pos + 1..])))
            .unwrap_or((&self, None))
    }
}