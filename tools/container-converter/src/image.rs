use async_trait::async_trait;
use docker_image_reference::Reference as DockerReference;
use futures::StreamExt;
use log::{debug, error, info, warn};
use serde::Deserialize;
use shiplift::{BuildOptions, ContainerOptions, Docker, Image, PullOptions, RegistryAuth, RmContainerOptions, TagOptions};
use shiplift::container::ContainerCreateInfo;
use shiplift::image::{ImageDetails, PushOptions};

use crate::{ConverterError, ConverterErrorKind, ImageKind, ImageToClean};
use crate::image_builder::run_subprocess;
use api_model::AuthConfig;
use api_model::shared::{UserProgramConfig, WorkingDir};

use std::env;
use std::fs;
use std::collections::HashSet;
use std::ops::Deref;
use std::path::Path;
use std::sync::mpsc;
use std::sync::mpsc::Sender;

#[derive(Deserialize)]
pub(crate) struct NitroCliOutput {
    #[serde(rename(deserialize = "Measurements"))]
    pub(crate) pcr_list: PCRList,
}

#[derive(Deserialize)]
pub(crate) struct PCRList {
    #[serde(alias = "PCR0")]
    pub(crate) pcr0: String,
    #[serde(alias = "PCR1")]
    pub(crate) pcr1: String,
    #[serde(alias = "PCR2")]
    pub(crate) pcr2: String,
    /// Only present if enclave file is built with signing certificate
    #[serde(alias = "PCR8")]
    pub(crate) pcr8: Option<String>,
}

pub(crate) async fn create_nitro_image(image: &DockerReference<'_>, output_file: &Path) -> Result<NitroCliOutput, ConverterError> {
    let output = output_file.to_str().ok_or(ConverterError {
        message: format!("Failed to cast path {:?} to string", output_file),
        kind: ConverterErrorKind::NitroFileCreation,
    })?;

    let image_as_str = image.to_string();

    let nitro_cli_args = [
        "build-enclave".as_ref(),
        "--docker-uri".as_ref(),
        image_as_str.as_ref(),
        "--output-file".as_ref(),
        output.as_ref(),
    ];

    let process_output = run_subprocess("nitro-cli".as_ref(), &nitro_cli_args)
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::NitroFileCreation,
        })?;

    serde_json::from_str::<NitroCliOutput>(&process_output).map_err(|err| ConverterError {
        message: format!("Bad measurements. {:?}", err),
        kind: ConverterErrorKind::NitroFileCreation,
    })
}

/// Convenience functions to work with docker daemon
#[async_trait]
pub(crate) trait DockerUtil: Send + Sync {
    async fn get_image(&self, image: &DockerReference<'_>) -> Result<ImageDetails, String>;

    async fn load_image(&self, tar_path: &str) -> Result<(), String>;

    async fn push_image(&self, image: &ImageWithDetails) -> Result<(), String>;

    async fn create_image(&self, docker_dir: &Path, image: &DockerReference<'_>) -> Result<(), String>;

    async fn create_container(&self, image: &DockerReference<'_>) -> Result<ContainerCreateInfo, String>;

    async fn force_delete_container(&self, container_name: &str) -> Result<(), String>;

    async fn export_container_file_system(&self, container_name: &str) -> Result<Vec<u8>, String>;

    async fn export_image_file_system(&self, image: &DockerReference<'_>) -> Result<Vec<u8>, String> {
        let container_info = self.create_container(image).await?;
        let result = self.export_container_file_system(&container_info.id).await?;

        // container is used only to export image file system
        // after we finish the export the container has no use for us and can be deleted
        self.force_delete_container(&container_info.id).await?;

        info!("Deleted container {}", container_info.id);

        Ok(result)
    }
}

pub(crate) struct ImageWithDetails<'a> {
    pub(crate) reference: DockerReference<'a>,

    pub(crate) details: ImageDetails,
}

impl<'a> ImageWithDetails<'a> {
    pub(crate) fn create_user_program_config(&self) -> Result<UserProgramConfig, ConverterError> {
        let config = &self.details.config;

        let (entry_point, arguments) = if let Some(ref raw_entry_point) = config.entrypoint {
            let (entry_point, mut entry_point_arguments) =
                ImageWithDetails::extract_entry_point_with_arguments(raw_entry_point)?;

            let mut cmd_argument_list = config.cmd.as_ref().unwrap_or(&Vec::new()).clone();

            entry_point_arguments.append(&mut cmd_argument_list);

            (entry_point, entry_point_arguments)
        } else {
            let cmd = config.cmd.as_ref().ok_or(ConverterError {
                message: "Input image must have a CMD clause if ENTRYPOINT is not present.".to_string(),
                kind: ConverterErrorKind::BadRequest,
            })?;

            ImageWithDetails::extract_entry_point_with_arguments(cmd)?
        };

        Ok(UserProgramConfig {
            entry_point,
            arguments,
            working_dir: self.working_dir(),
        })
    }

    pub(crate) fn working_dir(&self) -> WorkingDir {
        WorkingDir::from(self.details.config.working_dir.clone())
    }

    pub(crate) fn make_temporary(self, kind: ImageKind, sender: Sender<ImageToClean>) -> TempImage<'a> {
        TempImage {
            image: self,
            kind,
            sender,
        }
    }

    // Extracts first 12 unique bytes of id
    pub(crate) fn short_id(&self) -> &str {
        let id = &self.details.id;

        if id.starts_with("sha256:") {
            &id[7..19]
        } else {
            &id[..12]
        }
    }

    fn extract_entry_point_with_arguments(command: &Vec<String>) -> Result<(String, Vec<String>), ConverterError> {
        if command.is_empty() {
            return Err(ConverterError {
                message: "CMD OR ENTRYPOINT cannot be empty".to_string(),
                kind: ConverterErrorKind::BadRequest,
            });
        }

        if command.len() > 1 {
            Ok((command[0].clone(), command[1..].to_vec()))
        } else {
            Ok((command[0].clone(), Vec::new()))
        }
    }
}

// An image that deletes itself from a local docker repository
// when it goes out of scope
pub(crate) struct TempImage<'a> {
    pub(crate) image: ImageWithDetails<'a>,

    pub(crate) kind: ImageKind,

    pub(crate) sender: mpsc::Sender<ImageToClean>,
}

impl<'a> Drop for TempImage<'a> {
    fn drop(&mut self) {
        let result = ImageToClean {
            name: self.image.reference.to_string(),
            kind: self.kind.clone(),
        };

        if let Err(e) = self.sender.send(result) {
            warn!(
                "Failed sending image {} to resource cleaner task. {:?}",
                self.image.reference, e
            );
        }
    }
}

impl<'a> Deref for TempImage<'a> {
    type Target = ImageWithDetails<'a>;

    fn deref(&self) -> &Self::Target {
        &self.image
    }
}

pub(crate) struct DockerDaemon {
    docker: Docker,
    credentials: RegistryAuth,
}

impl DockerDaemon {
    pub(crate) fn new(credentials: &Option<AuthConfig>) -> Self {
        let docker = Docker::new();

        let credentials = {
            let mut builder = RegistryAuth::builder();

            if let Some(creds) = credentials {
                builder.username(&creds.username);
                builder.password(&creds.password);
            }
            builder.build()
        };

        DockerDaemon { docker, credentials }
    }

    async fn get_remote_image(&self, image: &DockerReference<'_>) -> Result<Option<ImageDetails>, String> {
        self.pull_image(image).await?;

        Ok(self.get_local_image(image).await)
    }

    async fn get_local_image(&self, address: &DockerReference<'_>) -> Option<ImageDetails> {
        let image = self.docker.images().get(address.to_string());

        match image.inspect().await {
            Ok(details) => Some(details),
            Err(err) => {
                warn!(
                    "Encountered error when searching for local image {}. {:?}. Assuming image not found.",
                    address.to_string(),
                    err
                );
                None
            }
        }
    }

    pub fn image_download_hazard_check(image_size: u64) -> Result<(), String> {
        debug!("image_size >= {} B", image_size);
        const MAX_COMPRESSED_IMAGE_BYTES: u64 = 3 * 1024 * 1024 * 1024;  // 3 GB

        // Heuristic: subject to change.
        let hazard = image_size > MAX_COMPRESSED_IMAGE_BYTES;

        if hazard {
            let image_size_mb = bytes_to_mebibytes(image_size);
            let max_mb = bytes_to_mebibytes(MAX_COMPRESSED_IMAGE_BYTES);
            return Err(format!("compressed image size >= {:.3} MiB > {:.3} MiB maximum",
                               image_size_mb, max_mb));
        }

        Ok(())
    }

    async fn pull_image(&self, address: &DockerReference<'_>) -> Result<(), String> {
        let mut pull_options = PullOptions::builder();
        pull_options.image(address.name());
        pull_options.auth(self.credentials.clone());

        if let Some(tag) = address.tag() {
            pull_options.tag(tag);
        }

        let mut stream = self.docker.images().pull(&pull_options.build());

        let mut layers = HashSet::new();
        let mut total_bytes: u64 = 0;
        while let Some(pull_result) = stream.next().await {
            match pull_result {
                Ok(output) => {
                    debug!("{:?}", output);
                    if let Some((layer_id, layer_bytes)) = output.image_layer_bytes() {
                        // We have layer information.
                        if !layers.contains(&layer_id) {
                            // This is a new layer.
                            total_bytes += layer_bytes;
                            layers.insert(layer_id.clone());
                            info!("\n{} image layer {} compressed bytes: {} ({:.3} MB total so far)",
                                        address, &layer_id, layer_bytes, total_bytes as f64 / (1024.0 * 1024.0));
                            if let Err(msg) = Self::image_download_hazard_check(total_bytes) {
                                let err_msg = format!("Aborting {} image download: system stability hazard: {}",
                                            address, msg);
                                error!("{}", err_msg);
                                return Err(err_msg);
                            }
                        }
                    }
                }
                Err(e) => return Err(format!("{}", e)),
            }
        }

        Ok(())
    }
}

#[async_trait]
impl DockerUtil for DockerDaemon {
    async fn get_image(&self, image: &DockerReference<'_>) -> Result<ImageDetails, String> {
        if let Some(local_image) = self.get_local_image(&image).await {
            Ok(local_image)
        } else {
            debug!(
                "Image {} not found in local repository, pulling from remote.",
                image.to_string()
            );
            self.get_remote_image(image)
                .await
                .and_then(|e| e.ok_or(format!("Image {} not found.", image.to_string())))
        }
    }

    async fn load_image(&self, tar_path: &str) -> Result<(), String> {
        let tar = fs::File::open(tar_path).map_err(|err| format!("Unable to open image file - {:?} : {:?}", tar_path, err))?;

        let reader = Box::from(tar);
        let mut stream = self.docker.images().import(reader);

        while let Some(import_result) = stream.next().await {
            match import_result {
                Ok(output) => {
                    info!("{:?}", output);
                }
                Err(e) => {
                    return Err(format!(
                        "Unable to load docker image {:?} - is docker socket accessible? : {:?}",
                        tar_path, e
                    ));
                }
            }
        }

        Ok(())
    }

    async fn push_image(&self, image: &ImageWithDetails) -> Result<(), String> {
        let repository = image.reference.name();
        let mut tag_options = TagOptions::builder();
        tag_options.repo(repository);

        let mut push_options = PushOptions::builder();
        push_options.auth(self.credentials.clone());

        if let Some(tag_value) = image.reference.tag() {
            tag_options.tag(tag_value);
            push_options.tag(tag_value.to_string());
        }

        let image_interface = Image::new(&self.docker, image.reference.to_string());

        image_interface.tag(&tag_options.build()).await.map_err(|err| {
            format!(
                "Failed to tag image {} with repo {}. Err {:?}",
                image.details.id,
                image.reference.to_string(),
                err
            )
        })?;

        self.docker
            .images()
            .push(repository, &push_options.build())
            .await
            .map_err(|err| {
                format!(
                    "Failed to push image {} into repo {}. Err: {:?}",
                    image.details.id, repository, err
                )
            })
    }

    async fn create_image(&self, docker_dir: &Path, image: &DockerReference<'_>) -> Result<(), String> {
        let path_as_string = docker_dir
            .as_os_str()
            .to_str()
            .ok_or(format!("Failed to convert path {} to UTF8 string.", docker_dir.display()))?;

        let mut build_opts_builder = BuildOptions::builder(path_as_string);
        let build_options = build_opts_builder.set_skip_gzip(true).tag(image.to_string()).build();

        env::set_var("DOCKER_BUILDKIT", "1");

        info!("Started building image");

        let mut stream = self.docker.images().build(&build_options);
        while let Some(build_result) = stream.next().await {
            match build_result {
                Ok(output) => {
                    info!("{:?}", output);
                }
                Err(e) => {
                    error!("{:?}", e);
                    return Err(format!("Docker build failed with: {}", e));
                }
            }
        }

        Ok(())
    }

    async fn create_container(&self, image: &DockerReference<'_>) -> Result<ContainerCreateInfo, String> {
        self.docker
            .containers()
            .create(&ContainerOptions::builder(&image.to_string()).build())
            .await
            .map_err(|err| format!("Failed creating docker container from image {}. {:?}.", image.name(), err))
    }

    async fn force_delete_container(&self, container_name: &str) -> Result<(), String> {
        let remove_options = RmContainerOptions::builder().force(true).build();

        self.docker
            .containers()
            .get(container_name)
            .remove(remove_options)
            .await
            .map_err(|err| format!("Failed deleting docker container {}. {:?}.", container_name, err))
    }

    async fn export_container_file_system(&self, container_name: &str) -> Result<Vec<u8>, String> {
        let mut result = Vec::new();
        let mut stream = Box::pin(self.docker.containers().get(container_name).export());

        while let Some(export_result) = stream.next().await {
            match export_result {
                Ok(mut output) => {
                    result.append(&mut output);
                }
                Err(e) => {
                    error!("{:?}", e);
                    return Err(format!("Docker export for container {} failed.{:?}", container_name, e));
                }
            }
        }

        Ok(result)
    }
}

fn bytes_to_mebibytes(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}
