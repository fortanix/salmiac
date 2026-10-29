/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::net::IpAddr;

use api_model::converter::AuthConfig;
use async_trait::async_trait;
use docker_image_reference::{Reference as DockerReference, Reference};
use futures::StreamExt;
use log::{debug, error, info, warn};
use shiplift::container::ContainerCreateInfo;
use shiplift::image::{BuildParams, ImageBuildChunk, ImageDetails, PushOptions};
use shiplift::{
    ContainerOptions, Docker, Image, PullOptions, RegistryAuth, RmContainerOptions, TagOptions,
};
use url::{Host, Url};

use crate::image::ImageWithDetails;

/// Convenience functions to work with docker daemon
#[async_trait]
pub trait DockerUtil: Send + Sync {
    async fn get_latest_image_details(
        &self,
        image: &DockerReference<'_>,
    ) -> Result<ImageDetails, String>;

    async fn get_local_image_details(
        &self,
        image: &DockerReference<'_>,
    ) -> Result<ImageDetails, String>;

    async fn load_image(&self, tar_path: &str) -> Result<String, String>;

    async fn push_image(&self, image: &ImageWithDetails) -> Result<(), String>;

    async fn build_image_from_archive(
        &self,
        archive: fs::File,
        image: &DockerReference<'_>,
    ) -> Result<(), String>;

    async fn create_container(
        &self,
        image: &DockerReference<'_>,
    ) -> Result<ContainerCreateInfo, String>;

    async fn force_delete_container(&self, container_name: &str) -> Result<(), String>;

    async fn export_container_file_system(
        &self,
        container_name: &str,
        file: &mut File,
    ) -> Result<(), String>;

    async fn export_image_file_system(
        &self,
        image: &DockerReference<'_>,
        file: &mut File,
    ) -> Result<(), String> {
        let container_info = self.create_container(image).await?;
        self.export_container_file_system(&container_info.id, file)
            .await?;

        // container is used only to export image file system
        // after we finish the export the container has no use for us and can be deleted
        self.force_delete_container(&container_info.id).await?;

        info!("Deleted container {}", container_info.id);

        Ok(())
    }

    async fn create_image_from_archive<'a>(
        &self,
        image: DockerReference<'a>,
        archive_file: File,
    ) -> Result<ImageWithDetails<'a>, String> {
        self.build_image_from_archive(archive_file, &image).await?;

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

        DockerDaemon {
            docker,
            credentials,
        }
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

    pub fn image_download_hazard_check(image_size: u64) -> Result<(), String> {
        fn bytes_to_mebibytes(bytes: u64) -> f64 {
            bytes as f64 / (1024.0 * 1024.0)
        }

        debug!("image_size >= {} B", image_size);
        const DEFAULT_MAX_COMPRESSED_IMAGE_BYTES: u64 = 3 * 1024 * 1024 * 1024; // 3 GB is the default value
        let max_compressed_image_bytes: u64 = option_env!("MAX_COMPRESSED_IMAGE_BYTES")
            .and_then(|size| size.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_COMPRESSED_IMAGE_BYTES);
        debug!("max compresses image size {}", max_compressed_image_bytes);
        // Heuristic: subject to change.
        let hazard = image_size > max_compressed_image_bytes;

        if hazard {
            let image_size_mb = bytes_to_mebibytes(image_size);
            let max_mb = bytes_to_mebibytes(max_compressed_image_bytes);
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
                                let message = format!(
                                    "Aborting {} image download: system stability hazard: {}",
                                    address, msg
                                );
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

const PULL_FAILED: &str = "image could not be pulled";

/// Local development only: set ALLOW_INTERNAL_REGISTRIES=1 to pull from or push to
/// localhost/private registries (for example when running the converter CLI by hand).
/// Never set this in the deployed service. Delete this function if you do not want an opt-out.
fn internal_registries_allowed() -> bool {
    std::env::var("ALLOW_INTERNAL_REGISTRIES").map_or(false, |v| v == "1")
}

/// Returns the registry host (with optional port) if the image names one.
/// Docker rule: the first path part is a registry only if it contains '.' or ':',
/// is "localhost", or is a bracketed IPv6 literal. Otherwise the image is on Docker Hub.
fn registry_host(image: &str) -> Option<&str> {
    let (first, _) = image.split_once('/')?;
    (first.contains('.')
        || first.contains(':')
        || first.contains('@')
        || first.starts_with('[')
        || first.eq_ignore_ascii_case("localhost"))
    .then_some(first)
}

/// Sync, no DNS. Ok(None) = nothing to resolve (Docker Hub, or opt-out set).
pub(crate) fn check_registry_syntax(image: &str) -> Result<Option<(Host<String>, u16)>, String> {
    if internal_registries_allowed() {
        return Ok(None);
    }
    let deny = |reason: &str| {
        warn!("registry check rejected image {}: {}", image, reason);
        PULL_FAILED.to_string()
    };
    let Some(reg) = registry_host(image) else {
        return Ok(None); // Docker Hub
    };
    let url =
        Url::parse(&format!("https://{}", reg)).map_err(|_| deny("unparsable registry host"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(deny("userinfo in registry host"));
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let host = url
        .host()
        .ok_or_else(|| deny("missing registry host"))?
        .to_owned();
    match &host {
        Host::Ipv4(ip) if blocked(IpAddr::V4(*ip)) => Err(deny("blocked IPv4 address")),
        Host::Ipv6(ip) if blocked(IpAddr::V6(*ip)) => Err(deny("blocked IPv6 address")),
        Host::Domain(d) => {
            let d = d.trim_end_matches('.');
            if d.eq_ignore_ascii_case("localhost") || d.to_ascii_lowercase().ends_with(".localhost")
            {
                return Err(deny("localhost"));
            }
            Ok(Some((host.clone(), port)))
        }
        _ => Ok(Some((host.clone(), port))),
    }
}

/// Full check: syntax, then resolve domain names and reject if ANY answer is blocked.
async fn ensure_registry_allowed(image: impl AsRef<str>) -> Result<(), String> {
    let image = image.as_ref();
    if let Some((Host::Domain(d), port)) = check_registry_syntax(image)? {
        let d = d.trim_end_matches('.').to_string();
        let addrs = tokio::net::lookup_host((d.as_str(), port))
            .await
            .map_err(|_| {
                warn!(
                    "registry check rejected image {}: DNS resolution failed",
                    image
                );
                PULL_FAILED.to_string()
            })?;
        for a in addrs {
            if blocked(a.ip()) {
                warn!(
                    "registry check rejected image {}: hostname resolves to a blocked address",
                    image
                );
                return Err(PULL_FAILED.to_string());
            }
        }
    }
    Ok(())
}

fn blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return blocked(IpAddr::V4(v4));
            }
            let s = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s & 0xfe00) == 0xfc00 // fc00::/7
                || (s & 0xffc0) == 0xfe80 // fe80::/10
        }
    }
}

#[async_trait]
impl DockerUtil for DockerDaemon {
    async fn get_latest_image_details(
        &self,
        image: &DockerReference<'_>,
    ) -> Result<ImageDetails, String> {
        // Reject internal registries before anything is dialed.
        ensure_registry_allowed(image.name().to_string()).await?;

        // Do a pull first to make sure that we always pick the latest image version from remote repository
        match self.pull_image(image).await {
            Err(shiplift::Error::Fault { code, .. }) if code == http::StatusCode::NOT_FOUND => {
                debug!(
                    "Image {} not found in remote repository, checking local.",
                    image.to_string()
                );
            }
            Err(err) => {
                // Raw daemon error stays in the logs; the caller gets a generic message.
                error!(
                    "Failed pulling image {} from remote repository. {:?}",
                    image.to_string(),
                    err
                );
                return Err(PULL_FAILED.to_string());
            }
            Ok(_) => {}
        }

        // Same message as a failed pull, so "not found" and "refused" look identical.
        self.get_local_image_details(&image).await.map_err(|e| {
            warn!("{}", e);
            PULL_FAILED.to_string()
        })
    }

    async fn get_local_image_details(&self, image: &Reference<'_>) -> Result<ImageDetails, String> {
        self.get_local_image(&image).await.ok_or(format!(
            "Image {} not found in local repository.",
            image.to_string()
        ))
    }

    async fn load_image(&self, tar_path: &str) -> Result<String, String> {
        let tar = fs::File::open(tar_path)
            .map_err(|err| format!("Unable to open image file - {:?} : {:?}", tar_path, err))?;

        let reader = Box::from(tar);
        let mut stream = self.docker.images().import(reader);

        let mut loaded_image_name: Option<String> = None;

        while let Some(import_result) = stream.next().await {
            match import_result {
                Ok(output) => {
                    info!("{:?}", output);

                    match output {
                        ImageBuildChunk::Update { stream } => {
                            if let Some(image_name) = stream.strip_prefix("Loaded image: ") {
                                if loaded_image_name.is_none() {
                                    loaded_image_name = Some(image_name.trim().to_owned());
                                } else {
                                    return Err(format!(
                                        "Loaded docker image {:?} contains more than one valid images. Previously loaded image was {:?}, while another image is {:?}",
                                        tar_path,
                                        loaded_image_name.unwrap(),
                                        image_name
                                    ));
                                }
                            }
                        }
                        _ => (),
                    }
                }
                Err(e) => {
                    return Err(format!(
                        "Unable to load docker image {:?} - is docker socket accessible? : {:?}",
                        tar_path, e
                    ));
                }
            }
        }

        match loaded_image_name {
            Some(name) => Ok(name),
            None => Err(format!(
                "Image loading is completed, but no image is loaded."
            )),
        }
    }

    async fn push_image(&self, image: &ImageWithDetails) -> Result<(), String> {
        let repository = image.reference.name();
        // The output registry is also dialed (and receives credentials), so check it too.
        ensure_registry_allowed(repository.to_string()).await?;

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

        image_interface
            .tag(&tag_options.build())
            .await
            .map_err(|err| {
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

    async fn build_image_from_archive(
        &self,
        archive: File,
        image: &Reference<'_>,
    ) -> Result<(), String> {
        let build_context = FrameFileRead::new(archive);

        let mut build_params = BuildParams::default();
        build_params.tag(image.to_string());

        // Disable buildkit as it makes converted images hang on CI machine with a docker version 20.10.25.
        // The issue was found while working on RTE-324.
        //env::set_var("DOCKER_BUILDKIT", "1");

        info!("Started building image {}", image.to_string());

        let mut stream = self
            .docker
            .images()
            .build_from_raw_parts(&build_params, build_context);
        while let Some(build_result) = stream.next().await {
            match build_result {
                // ImageBuildChunk::Error returns error and error_detail
                // error has same content as error_detail.message; Hence picked
                // only error_detail instead.
                Ok(ImageBuildChunk::Error { error_detail, .. }) => {
                    error!("{:?}", error_detail);
                    return Err(format!("Docker build failed with: {:?}", error_detail));
                }
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

    async fn create_container(
        &self,
        image: &DockerReference<'_>,
    ) -> Result<ContainerCreateInfo, String> {
        self.docker
            .containers()
            .create(&ContainerOptions::builder(&image.to_string()).build())
            .await
            .map_err(|err| {
                format!(
                    "Failed creating docker container from image {}. {:?}.",
                    image.name(),
                    err
                )
            })
    }

    async fn force_delete_container(&self, container_name: &str) -> Result<(), String> {
        let remove_options = RmContainerOptions::builder().force(true).build();

        self.docker
            .containers()
            .get(container_name)
            .remove(remove_options)
            .await
            .map_err(|err| {
                format!(
                    "Failed deleting docker container {}. {:?}.",
                    container_name, err
                )
            })
    }

    async fn export_container_file_system(
        &self,
        container_name: &str,
        file: &mut File,
    ) -> Result<(), String> {
        info!(
            "Started file system export of a container {}...",
            container_name
        );
        let mut stream = Box::pin(self.docker.containers().get(container_name).export());

        while let Some(export_result) = stream.next().await {
            match export_result {
                Ok(output) => {
                    file.write_all(&output).map_err(|err| {
                        format!("Failed writing to container fs archive. {:?}", err)
                    })?;
                }
                Err(e) => {
                    error!("{:?}", e);
                    return Err(format!(
                        "Docker export for container {} failed.{:?}",
                        container_name, e
                    ));
                }
            }
        }

        Ok(())
    }
}

struct FrameFileRead {
    file: std::fs::File,
}

impl FrameFileRead {
    pub fn new(file: std::fs::File) -> Self {
        FrameFileRead { file }
    }
}

impl Iterator for FrameFileRead {
    type Item = std::result::Result<Vec<u8>, shiplift::errors::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = [0 as u8; 1 * 1024 * 1024];

        match self.file.read(&mut buf) {
            Ok(amount) if amount > 0 => Some(Ok(buf[..amount].to_vec())),
            Err(err) => Some(Err(shiplift::errors::Error::IO(err))),
            Ok(_) => None,
        }
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::*;

    #[tokio::test]
    async fn rejects_internal_registries() {
        for n in [
            "127.0.0.1:2375/x",
            "127.0.0.1:9092/x:latest",
            "localhost/x",
            "localhost./x",
            "LOCALHOST:5000/x",
            "0x7f.1/x",
            "0177.0.0.1/x",
            "127.1/x",
            "[::1]:5000/x",
            "[::ffff:127.0.0.1]/x",
            "10.233.125.150:9093/x",
            "10.7.202.11:10250/x",
            "169.254.169.254/x",
            "100.64.0.1/x",
            "u:p@host.io/x",
        ] {
            assert!(
                ensure_registry_allowed(n).await.is_err(),
                "should reject {n}"
            );
        }
    }

    #[tokio::test]
    async fn accepts_docker_hub_names_without_dns() {
        for n in [
            "alpine",
            "alpine:latest",
            "library/alpine:3.19",
            "myuser/app:1.0",
        ] {
            assert!(
                ensure_registry_allowed(n).await.is_ok(),
                "should accept {n}"
            );
        }
    }

    #[test]
    fn registry_host_cases() {
        assert_eq!(registry_host("alpine"), None);
        assert_eq!(registry_host("library/alpine"), None);
        assert_eq!(registry_host("ghcr.io/a/b:1"), Some("ghcr.io"));
        assert_eq!(registry_host("localhost:5000/x"), Some("localhost:5000"));
        assert_eq!(registry_host("[::1]:5000/x"), Some("[::1]:5000"));
    }

    #[test]
    fn blocked_ranges() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(blocked(ip.parse().unwrap()), "should block {ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(!blocked(ip.parse().unwrap()), "should allow {ip}");
        }
    }
}
