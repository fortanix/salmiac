use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::{env, fs};

use api_model::AuthConfig;
use async_trait::async_trait;
use docker_image_reference::{Reference as DockerReference, Reference};
use futures::StreamExt;
use log::{debug, error, info, warn};
use shiplift::container::ContainerCreateInfo;
use shiplift::image::{ImageDetails, PushOptions};
use shiplift::{BuildOptions, ContainerOptions, Docker, Image, PullOptions, RegistryAuth, RmContainerOptions, TagOptions};

use crate::image::ImageWithDetails;

/// Convenience functions to work with docker daemon
#[async_trait]
pub trait DockerUtil: Send + Sync {
    async fn get_latest_image_details(&self, image: &DockerReference<'_>) -> Result<ImageDetails, String>;

    async fn get_local_image_details(&self, image: &DockerReference<'_>) -> Result<ImageDetails, String>;

    async fn load_image(&self, tar_path: &str) -> Result<(), String>;

    async fn push_image(&self, image: &ImageWithDetails) -> Result<(), String>;

    async fn build_image(&self, docker_dir: &Path, image: &DockerReference<'_>) -> Result<(), String>;

    async fn create_container(&self, image: &DockerReference<'_>) -> Result<ContainerCreateInfo, String>;

    async fn force_delete_container(&self, container_name: &str) -> Result<(), String>;

    async fn export_container_file_system(&self, container_name: &str, file: &mut File) -> Result<(), String>;

    async fn export_image_file_system(&self, image: &DockerReference<'_>, file: &mut File) -> Result<(), String> {
        let container_info = self.create_container(image).await?;
        self.export_container_file_system(&container_info.id, file).await?;

        // container is used only to export image file system
        // after we finish the export the container has no use for us and can be deleted
        self.force_delete_container(&container_info.id).await?;

        info!("Deleted container {}", container_info.id);

        Ok(())
    }

    async fn create_image<'a>(&self, image: DockerReference<'a>, dir: &Path) -> Result<ImageWithDetails<'a>, String> {
        self.build_image(dir, &image).await?;

        let details = self.get_local_image_details(&image).await?;

        Ok(ImageWithDetails {
            reference: image,
            details,
        })
    }
}

pub struct DockerDaemon {
    docker: Docker,
    credentials: Option<RegistryAuth>,
}

impl DockerDaemon {
    pub fn new(credentials_arg: &Option<AuthConfig>) -> Self {
        let docker = Docker::new();

        let credentials = credentials_arg.as_ref().map(|creds| {
            let mut builder = RegistryAuth::builder();

            builder.username(&creds.username);
            builder.password(&creds.password);

            builder.build()
        });

        DockerDaemon { docker, credentials }
    }

    async fn get_local_image(&self, address: &DockerReference<'_>) -> Option<ImageDetails> {
        let image = self.docker.images().get(address.to_string());

        match image.inspect().await {
            Ok(details) => Some(details),
            Err(err) => {
                warn!(
                    "Encountered error when searching for local image {}. {:?}.",
                    address.to_string(),
                    err
                );
                None
            }
        }
    }

    fn image_download_hazard_check(image_size: u64) -> Result<(), String> {
        fn bytes_to_mebibytes(bytes: u64) -> f64 {
            bytes as f64 / (1024.0 * 1024.0)
        }

        debug!("image_size >= {} B", image_size);
        const MAX_COMPRESSED_IMAGE_BYTES: u64 = 3 * 1024 * 1024 * 1024; // 3 GB

        // Heuristic: subject to change.
        let hazard = image_size > MAX_COMPRESSED_IMAGE_BYTES;

        if hazard {
            let image_size_mb = bytes_to_mebibytes(image_size);
            let max_mb = bytes_to_mebibytes(MAX_COMPRESSED_IMAGE_BYTES);
            return Err(format!(
                "compressed image size >= {:.3} MiB > {:.3} MiB maximum",
                image_size_mb, max_mb
            ));
        }

        Ok(())
    }

    async fn pull_image(&self, address: &DockerReference<'_>) -> Result<(), shiplift::Error> {
        let mut pull_options = PullOptions::builder();
        pull_options.image(address.name());

        if let Some(credentials) = self.credentials.clone() {
            pull_options.auth(credentials);
        }

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
                            info!(
                                "\n{} image layer {} compressed bytes: {} ({:.3} MB total so far)",
                                address,
                                &layer_id,
                                layer_bytes,
                                total_bytes as f64 / (1024.0 * 1024.0)
                            );
                            if let Err(msg) = Self::image_download_hazard_check(total_bytes) {
                                let message = format!("Aborting {} image download: system stability hazard: {}", address, msg);
                                error!("{}", message);

                                return Err(shiplift::Error::Fault {
                                    code: http::StatusCode::INTERNAL_SERVER_ERROR,
                                    message,
                                });
                            }
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[async_trait]
impl DockerUtil for DockerDaemon {
    async fn get_latest_image_details(&self, image: &DockerReference<'_>) -> Result<ImageDetails, String> {
        // Do a pull first to make sure that we always pick the latest image version from remote repository
        match self.pull_image(image).await {
            Err(shiplift::Error::Fault { code, .. }) if code == http::StatusCode::NOT_FOUND => {
                debug!("Image {} not found in remote repository, checking local.", image.to_string());
            }
            Err(err) => {
                return Err(format!(
                    "Failed pulling image {} from remote repository. {:?}",
                    image.to_string(),
                    err
                ))
            }
            Ok(_) => {}
        }

        self.get_local_image_details(&image).await
    }

    async fn get_local_image_details(&self, image: &Reference<'_>) -> Result<ImageDetails, String> {
        self.get_local_image(&image)
            .await
            .ok_or(format!("Image {} not found in local repository.", image.to_string()))
    }

    async fn load_image(&self, tar_path: &str) -> Result<(), String> {
        let tar = fs::File::open(tar_path).map_err(|err| format!("Unable to open image file - {:?} : {:?}", tar_path, err))?;

        let reader = Box::from(tar);
        let mut stream = self.docker.images().import(reader);

        while let Some(import_result) = stream.next().await {
            match import_result {
                Ok(output) => {
                    info!("{:?}", output)
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

        if let Some(credentials) = self.credentials.clone() {
            push_options.auth(credentials);
        }

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

    async fn build_image(&self, docker_dir: &Path, image: &DockerReference<'_>) -> Result<(), String> {
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

    async fn export_container_file_system(&self, container_name: &str, file: &mut File) -> Result<(), String> {
        let mut stream = Box::pin(self.docker.containers().get(container_name).export());

        while let Some(export_result) = stream.next().await {
            match export_result {
                Ok(output) => {
                    file.write_all(&output)
                        .map_err(|err| format!("Failed writing to container fs archive. {:?}", err))?;
                }
                Err(e) => {
                    error!("{:?}", e);
                    return Err(format!("Docker export for container {} failed.{:?}", container_name, e));
                }
            }
        }

        Ok(())
    }
}
