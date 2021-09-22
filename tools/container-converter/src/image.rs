use log::{info, error};
use shiplift::{Docker, Image, RegistryAuth, PullOptions, TagOptions};
use shiplift::image::{PushOptions, ImageDetails};
use futures::StreamExt;

use crate::DockerImageURL;

use std::process;
use std::env;
use std::fs;
use std::path::Path;

pub fn create_nitro_image(image_name : &str, output_file : &Path) -> Result<(), String> {
    let output = output_file.to_str().unwrap();

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
        process_output(output)
    })
}

fn process_output(output : process::Output) -> Result<(), String> {
    if !output.status.success() {
        error!("status: {}", output.status);
        error!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        Err(format!("Process exited with code {:?}", output.status.code()))
    } else {
        info!("status: {}", output.status);
        info!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        Ok(())
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
    pub fn new(username : String, password : String) -> Self {
        let docker = Docker::new();

        let credentials = RegistryAuth::builder()
            .username(username)
            .password(password)
            .build();

        DockerUtil {
            docker,
            credentials
        }
    }

    pub async fn get_remote_image(&self, image : &str) -> Result<ImageWithDetails<'_>, String> {
        self.pull_image(image).await?;

        Ok(self.get_local_image(&image).await.expect("Failed to pull image"))
    }

    pub async fn get_local_image(&self, name : &str) -> Option<ImageWithDetails<'_>> {
        let image = self.docker.images().get(name);

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

    pub async fn push_image(&self, image : &ImageWithDetails<'_>, output_address: &str) -> Result<(), String> {
        let (repository, tag) = output_address.repository_and_tag();

        let tag_options = TagOptions::builder()
            .repo(repository)
            .tag(tag)
            .build();

        image.image.tag(&tag_options)
            .await
            .map_err(|err| format!("Failed to tag image {} with repo {} and tag {}. Err {:?}", image.details.id, repository, tag, err))?;

        let push_options = PushOptions::builder()
            .tag(tag.to_string())
            .auth(self.credentials.clone())
            .build();

        self.docker.images()
            .push(repository, &push_options)
            .await
            .map_err(|err| format!("Failed to push image {} into repo {} with tag {}. Err: {:?}", image.details.id, repository, tag, err))
    }

    pub fn create_image(&self, docker_dir: &Path, image_tag: &str) -> Result<(), String> {
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
            process_output(output)
        })
    }

    pub fn create_image_buildkit(&self, docker_dir: &str, image_tag: &str, output_file : &str) -> Result<(), String> {
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
            process_output(output)
        })
    }

    async fn pull_image(&self, image : &str) -> Result<(), String> {
        let (repository, tag) = image.repository_and_tag();

        let pull_options = PullOptions::builder()
            .image(repository)
            .tag(tag)
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