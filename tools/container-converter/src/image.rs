use log::{info, error, warn, debug};
use shiplift::{Docker, Image, RegistryAuth, PullOptions, TagOptions, BuildOptions};
use shiplift::image::{PushOptions, ImageDetails};
use futures::StreamExt;
use docker_image_reference::Reference as DockerReference;
use serde::Deserialize;
use api_model::AuthConfig;

use std::process;
use std::env;
use std::fs;
use std::path::Path;
use crate::{ConverterError, ConverterErrorKind};

#[derive(Deserialize)]

pub struct NitroCliOutput {
    #[serde(rename(deserialize = "Measurements"))]
    pub measurements: PCRList
}

#[derive(Deserialize)]
pub struct PCRList {
    #[serde(alias = "PCR0")]
    pub pcr0: String,
    #[serde(alias = "PCR1")]
    pub pcr1: String,
    #[serde(alias = "PCR2")]
    pub pcr2: String,
    /// Only present if enclave file is built with signing certificate
    #[serde(alias = "PCR8")]
    pub pcr8: Option<String>,
}

pub fn create_nitro_image(image_name : &str, output_file : &Path) -> Result<NitroCliOutput, ConverterError> {
    let output = output_file.to_str()
        .ok_or(ConverterError {
            message: format!("Failed to cast path {:?} to string", output_file),
            kind: ConverterErrorKind::NitroFileCreation
        })?;

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
        .map_err(|err| ConverterError {
            message: format!("Failure executing nitro-cli. {:?}", err),
            kind: ConverterErrorKind::NitroFileCreation
        })?;

    let process_output = process_output(nitro_cli_command, "nitro-cli")
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::NitroFileCreation,
        })?;

    serde_json::from_str::<NitroCliOutput>(&process_output)
        .map_err(|err| ConverterError {
            message: format!("Bad measurements. {:?}", err),
            kind: ConverterErrorKind::NitroFileCreation
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
    pub fn new(credentials : &Option<AuthConfig>) -> Self {
        let docker = Docker::new();

        let credentials = {
            let mut builder = RegistryAuth::builder();

            if let Some(creds) = credentials {
                builder.username(&creds.username);
                builder.password(&creds.password);
            }
            builder.build()
        };

        DockerUtil {
            docker,
            credentials
        }
    }

    pub async fn get_image(&self, image : &DockerReference<'_>) -> Result<ImageWithDetails<'_>, String> {
        if let Some(local_image) = self.get_local_image(&image).await {
            Ok(local_image)
        } else {
            debug!("Image {} not found in local repository, pulling from remote.", image.to_string());
            self.get_remote_image(image).await
                .and_then(|e| e.ok_or(format!("Image {} not found.", image.to_string())))
        }
    }

    async fn get_remote_image(&self, image : &DockerReference<'_>) -> Result<Option<ImageWithDetails<'_>>, String> {
        self.pull_image(image).await?;

        Ok(self.get_local_image(image).await)
    }

    async fn get_local_image(&self, address : &DockerReference<'_>) -> Option<ImageWithDetails<'_>> {
        let image = self.docker.images().get(address.to_string());

        match image.inspect().await {
            Ok(details) => {
                Some(ImageWithDetails {
                    image,
                    details,
                })
            }
            Err(err) => {
                warn!("Encountered error when searching for local image {}. {:?}. Assuming image not found.", address.to_string(), err);
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

    pub async fn create_image(&self, docker_dir: &Path, image_tag: &str) -> Result<(), String> {
        let path_as_string = docker_dir.as_os_str()
            .to_str()
            .ok_or(format!("Failed to convert path {} to UTF8 string.", docker_dir.display()))?;

        let build_options = BuildOptions::builder(path_as_string)
            .tag(image_tag)
            .build();

        env::set_var("DOCKER_BUILDKIT", "1");

        info!("Started building image");

        let mut stream = self.docker.images().build(&build_options);
        while let Some(build_result) = stream.next().await {
            match build_result {
                Ok(output) => {
                    info!("{:?}", output);
                },
                Err(e) => {
                    error!("{:?}", e);
                    return Err(format!("Docker build failed with: {}", e))
                },
            }
        }

        Ok(())
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
        let mut pull_options = PullOptions::builder();
        pull_options.image(address.name());
        pull_options.auth(self.credentials.clone());

        if let Some(tag) = address.tag() {
            pull_options.tag(tag);
        }

        let mut stream = self.docker
            .images()
            .pull(&pull_options.build());

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
