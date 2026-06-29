/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[cfg(platform = "nitro")]
pub(crate) mod nitro;
#[cfg(platform = "nitro")]
pub(crate) use self::nitro::EnclaveImageBuilder as PlatformEnclaveImageBuilder;

#[cfg(platform = "snp")]
pub(crate) mod snp;
#[cfg(platform = "snp")]
pub(crate) use self::snp::EnclaveImageBuilder as PlatformEnclaveImageBuilder;
#[cfg(platform = "snp")]
pub(crate) mod snp_measurement;

#[cfg(platform = "tdx")]
pub(crate) mod tdx;
#[cfg(platform = "tdx")]
pub(crate) use self::tdx::EnclaveImageBuilder as PlatformEnclaveImageBuilder;

#[cfg(platform = "simulator")]
pub(crate) mod simulator;
#[cfg(platform = "simulator")]
pub(crate) use self::simulator::EnclaveImageBuilder as PlatformEnclaveImageBuilder;

#[cfg(any(platform = "snp", platform = "tdx", platform = "simulator"))]
pub(crate) mod initramfs;
#[cfg(any(platform = "snp", platform = "tdx"))]
pub(crate) mod nvidia;
#[cfg(any(platform = "snp", platform = "tdx", platform = "simulator"))]
pub(crate) mod qemu;

use std::ffi::OsStr;
use std::fmt::Debug;
use std::fs;
use std::fs::File;
use std::io::{ErrorKind as IoErrorKind, Read, Seek};
use std::ops::Add;
use std::os::unix::fs as unix_fs;
use std::path::Path;

use api_model::converter::{CertificateConfig, ConverterOptions, DsmConfiguration};
#[cfg(platform = "nitro")]
use api_model::enclave::EnclaveManifest;
use api_model::enclave::{CcmBackendUrl, FileSystemConfig, UserConfig};
#[cfg(any(platform = "snp", platform = "tdx"))]
use api_model::EnclavesOptions;
#[cfg(any(platform = "snp", platform = "tdx"))]
use api_model::NvidiaDriverCapability;
use docker_image_reference::Reference as DockerReference;
use log::{debug, info, warn};
use nix::sys::statfs::statfs;
use nix::unistd::{chown, Uid};
#[cfg(platform = "nitro")]
use rand::distributions::{Alphanumeric, DistString};
use sys_mount::{Mount, Unmount, UnmountFlags};
use tar::Archive;
use tempfile::TempDir;

use crate::docker::DockerUtil;
use crate::file::Resource;
#[cfg(platform = "nitro")]
use crate::file::{BuildContext, DockerCopyArgs, DockerFile};
use crate::image::ImageWithDetails;
#[cfg(platform = "nitro")]
use crate::image_builder::INSTALLATION_DIR;
use crate::image_builder::{bytes_to_mb_ceil, path_as_str, rust_log_env_var, MEGA_BYTE};
use crate::{run_subprocess, ConverterError, ConverterErrorKind, Result};

const NVIDIA_DRIVER_PAYLOAD_ROOT: &str = "/opt/fortanix/enclave-os/nvidia-driver-payload";
const NVIDIA_DRIVER_TARGET_ROOT: &str = "opt/fortanix/nvidia-driver";
const NVIDIA_DRIVER_TARGET_LIB: &str = "opt/fortanix/nvidia-driver/lib";
const NVIDIA_DRIVER_TARGET_BIN: &str = "opt/fortanix/nvidia-driver/bin";

pub(crate) fn get_image_env(
    input_image: &ImageWithDetails<'_>,
    converter_options: &ConverterOptions,
) -> Vec<String> {
    let mut result = input_image
        .details
        .config
        .env
        .as_ref()
        .map(|e| e.clone())
        .unwrap_or(vec![]);

    // Docker `ENV` assigns environment variables by the order of definition, thus making
    // latest definition of the same variable override previous definition.
    // We exploit this logic to override variables from the `input_image` with the values from `conversion_request`
    // by adding all `conversion_request` variables to the end of `env_vars` vector.
    for request_env in &converter_options.env_vars {
        result.push(request_env.clone());
    }
    result
}
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct EnclaveSettings {
    pub(crate) user_name: String,

    pub(crate) env_vars: Vec<String>,

    pub(crate) is_debug: bool,

    pub(crate) enable_overlay_filesystem_persistence: bool,

    pub(crate) ccm_backend_url: CcmBackendUrl,

    pub(crate) dsm_configuration: DsmConfiguration,

    #[cfg(any(platform = "snp", platform = "tdx"))]
    pub(crate) gpu_passthrough: bool,

    #[cfg(any(platform = "snp", platform = "tdx"))]
    pub(crate) nvidia_driver_capabilities: Vec<String>,
}

impl EnclaveSettings {
    pub(crate) fn new(
        input_image: &ImageWithDetails<'_>,
        converter_options: &ConverterOptions,
        #[cfg(any(platform = "snp", platform = "tdx"))] enclaves_options: &EnclavesOptions,
    ) -> Self {
        EnclaveSettings {
            user_name: input_image.details.config.user.clone().unwrap_or_default(),
            env_vars: vec![rust_log_env_var("enclave")],
            is_debug: converter_options.debug.unwrap_or(false),
            enable_overlay_filesystem_persistence: converter_options
                .enable_overlay_filesystem_persistence
                .unwrap_or(false),
            ccm_backend_url: CcmBackendUrl::new(
                converter_options
                    .ccm_configuration
                    .clone()
                    .unwrap_or_default()
                    .ccm_url
                    .as_str(),
            )
            .unwrap_or_default(),
            dsm_configuration: converter_options
                .dsm_configuration
                .clone()
                .unwrap_or_default(),
            #[cfg(any(platform = "snp", platform = "tdx"))]
            gpu_passthrough: enclaves_options.enable_gpu_passthrough.unwrap_or(false),
            #[cfg(any(platform = "snp", platform = "tdx"))]
            nvidia_driver_capabilities: {
                if enclaves_options.enable_gpu_passthrough.unwrap_or(false) {
                    enclaves_options
                        .nvidia_driver_capabilities
                        .clone()
                        .unwrap_or_else(|| {
                            vec![
                                NvidiaDriverCapability::Compute,
                                NvidiaDriverCapability::Utility,
                            ]
                        })
                        .into_iter()
                        .map(|capability| capability.as_str().to_string())
                        .collect()
                } else {
                    vec![]
                }
            },
        }
    }
}

pub(crate) struct GenericEnclaveImageBuilder<'a> {
    pub(crate) client_image_reference: &'a DockerReference<'a>,

    pub(crate) dir: &'a TempDir,

    pub(crate) enclave_base_image: &'a DockerReference<'a>,
}

impl<'a> GenericEnclaveImageBuilder<'a> {
    pub(crate) const DEFAULT_ENCLAVE_SETTINGS_FILE: &'static str = "enclave-settings.json";

    pub(crate) const BLOCK_FILE_MOUNT_DIR: &'static str = "block-file-mount";

    pub(crate) const BLOCK_FILE_OUT: &'static str = "Blockfile.ext4";

    pub(crate) const BLOCK_FILE_SIZE_MULTIPLIER_INCREASE: f64 = 1.5; // 50% increase of the block file size

    pub(crate) const IMAGE_BUILD_DEPENDENCIES: &'static [Resource<'static>] = &[
        Resource {
            name: "enclave",
            data: include_bytes!("../../resources/enclave/enclave"),
            is_executable: true,
        },
        Resource {
            name: "enclave-startup",
            data: include_bytes!("../../resources/enclave/enclave-startup"),
            is_executable: true,
        },
    ];

    #[cfg(platform = "nitro")]
    pub(crate) const IMAGE_COPY_DEPENDENCIES: &'static [&'static str] =
        &["enclave", "enclave-settings.json", "enclave-startup"];

    pub(crate) async fn export_image_file_system(
        &self,
        docker_util: &dyn DockerUtil,
        archive_path: &Path,
    ) -> Result<Archive<File>> {
        self.export_docker_image_file_system(docker_util, archive_path, self.client_image_reference)
            .await
    }

    #[cfg(any(platform = "snp", platform = "tdx", platform = "simulator"))]
    pub(crate) async fn export_enclave_base_file_system(
        &self,
        docker_util: &dyn DockerUtil,
        archive_path: &Path,
    ) -> Result<Archive<File>> {
        self.export_docker_image_file_system(docker_util, archive_path, self.enclave_base_image)
            .await
    }

    async fn export_docker_image_file_system(
        &self,
        docker_util: &dyn DockerUtil,
        archive_path: &Path,
        docker_reference: &DockerReference<'_>,
    ) -> Result<Archive<File>> {
        let mut archive_file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&archive_path)
            .map_err(|err| ConverterError {
                message: format!(
                    "Failed creating image fs archive at {}. {:?}",
                    archive_path.display(),
                    err
                ),
                kind: ConverterErrorKind::ImageFileSystemExport,
            })?;

        docker_util
            .export_image_file_system(docker_reference, &mut archive_file)
            .await
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::ImageFileSystemExport,
            })?;

        archive_file.rewind().map_err(|err| ConverterError {
            message: format!(
                "Failed seek in image fs archive at {}. {:?}",
                archive_path.display(),
                err
            ),
            kind: ConverterErrorKind::ImageFileSystemExport,
        })?;

        Ok(Archive::new(archive_file))
    }

    #[cfg(platform = "nitro")]
    pub(crate) fn create_manifest_file(
        enclave_manifest: EnclaveManifest,
        build_context: &BuildContext,
    ) -> Result<()> {
        let data = serde_json::to_vec(&enclave_manifest).map_err(|err| ConverterError {
            message: format!("Failed serializing enclave settings file. {:?}", err),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        let resource = Resource {
            name: "enclave-settings.json",
            data: &data,
            is_executable: false,
        };

        build_context
            .create_resource(resource)
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })
    }

    pub(crate) async fn create_block_file(
        &self,
        docker_util: &dyn DockerUtil,
        user_config: &UserConfig,
    ) -> Result<FileSystemConfig> {
        self.create_block_file_with_optional_nvidia_driver_payload(docker_util, user_config, None)
            .await
    }

    #[cfg(any(platform = "snp", platform = "tdx"))]
    pub(crate) async fn create_block_file_with_nvidia_driver_payload(
        &self,
        docker_util: &dyn DockerUtil,
        user_config: &UserConfig,
        nvidia_driver_capabilities: &[String],
    ) -> Result<FileSystemConfig> {
        self.create_block_file_with_optional_nvidia_driver_payload(
            docker_util,
            user_config,
            Some(nvidia_driver_capabilities),
        )
        .await
    }

    async fn create_block_file_with_optional_nvidia_driver_payload(
        &self,
        docker_util: &dyn DockerUtil,
        user_config: &UserConfig,
        nvidia_driver_capabilities: Option<&[String]>,
    ) -> Result<FileSystemConfig> {
        let block_file_mount_dir = self.dir.path().join(Self::BLOCK_FILE_MOUNT_DIR);
        let block_file_out = self.dir.path().join(Self::BLOCK_FILE_OUT);

        fs::create_dir(&block_file_mount_dir).map_err(|err| ConverterError {
            message: format!(
                "Failed creating dir {}. {:?}",
                block_file_mount_dir.display(),
                err
            ),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        self.create_block_file0(
            &block_file_mount_dir,
            &block_file_out,
            user_config,
            docker_util,
            nvidia_driver_capabilities,
        )
        .await
    }

    #[cfg(platform = "nitro")]
    pub(crate) fn enclave_image(&self) -> String {
        self.retag_client_image(&Alphanumeric.sample_string(&mut rand::thread_rng(), 16))
    }

    #[cfg(platform = "nitro")]
    fn retag_client_image(&self, tag: &str) -> String {
        let new_tag = self
            .client_image_reference
            .tag()
            .map(|e| e.to_string() + "-" + tag)
            .unwrap_or("enclave".to_string());

        self.client_image_reference.name().to_string() + ":" + &new_tag
    }

    #[cfg(platform = "nitro")]
    pub(crate) fn create_requisites(
        &self,
        enclave_settings: EnclaveSettings,
        build_context: &BuildContext,
    ) -> std::result::Result<(), String> {
        let docker_file = self.docker_file_contents(enclave_settings);

        build_context.create_docker_file(&docker_file)?;

        build_context.create_resources(Self::IMAGE_BUILD_DEPENDENCIES)?;

        Ok(())
    }

    pub(crate) fn enclave_command_string(
        enclave_settings: &EnclaveSettings,
        install_dir: &Path,
        binary_name: &str,
    ) -> String {
        let enclave_bin = install_dir.join(binary_name);

        let enclave_settings_file = install_dir.join(Self::DEFAULT_ENCLAVE_SETTINGS_FILE);

        let user_name = {
            if let Some(pos) = enclave_settings.user_name.find(":") {
                &enclave_settings.user_name[..pos]
            } else {
                &enclave_settings.user_name
            }
        };

        // Quick fix for: https://fortanix.atlassian.net/browse/SALM-94
        // Sets the home variable specifically for applications that require it to run
        let switch_user_cmd = if user_name != "" && user_name != "root" {
            format!("export HOME=/home/{};", user_name)
        } else {
            String::new()
        };

        format!(
            "{} {} --vsock-port 5006 --settings-path {}",
            switch_user_cmd,
            enclave_bin.display(),
            enclave_settings_file.display()
        )
    }

    #[cfg(platform = "nitro")]
    fn docker_file_contents(&self, mut enclave_settings: EnclaveSettings) -> DockerFile {
        let install_dir_path = Path::new(INSTALLATION_DIR);

        let items = Self::IMAGE_COPY_DEPENDENCIES
            .iter()
            .map(|e| e.to_string())
            .collect();

        let add = DockerCopyArgs {
            items,
            destination: INSTALLATION_DIR.to_string() + "/",
        };

        let run_enclave_cmd =
            Self::enclave_command_string(&enclave_settings, install_dir_path, "enclave");

        enclave_settings.env_vars.push(rust_log_env_var("enclave"));

        DockerFile {
            from: self.enclave_base_image.to_string(),
            add: Some(add),
            env: enclave_settings.env_vars,
            run: None,
            cmd: Some(run_enclave_cmd),
            entrypoint: None,
        }
    }

    async fn create_block_file0(
        &self,
        mount_dir: &Path,
        block_file_out_path: &Path,
        user_config: &UserConfig,
        docker_util: &dyn DockerUtil,
        nvidia_driver_capabilities: Option<&[String]>,
    ) -> Result<FileSystemConfig> {
        async fn run_subprocess0<S: AsRef<OsStr> + Debug, A: AsRef<OsStr> + Debug>(
            subprocess_path: S,
            args: &[A],
        ) -> Result<String> {
            run_subprocess(subprocess_path, args)
                .await
                .map_err(|message| ConverterError {
                    message,
                    kind: ConverterErrorKind::BlockFileCreation,
                })
        }

        async fn get_available_disc_space(block_file_dir: &Path) -> Result<u64> {
            statfs(block_file_dir)
                .map(|e| e.block_size() as u64 * e.blocks_available())
                .map_err(|err| ConverterError {
                    message: format!(
                        "Failure retrieving available disc space using `statfs` for path {}. {:?}",
                        block_file_dir.display(),
                        err
                    )
                    .to_string(),
                    kind: ConverterErrorKind::BlockFileCreation,
                })
        }

        async fn create_block_file(
            working_dir: &Path,
            block_file_out_path: &Path,
            size_bytes: u64,
        ) -> Result<()> {
            let available_disc_space = get_available_disc_space(working_dir).await?;

            if available_disc_space < size_bytes {
                return Err(ConverterError {
                    message: format!(
                        "Available disk space: {} Required disk space: {}",
                        available_disc_space, size_bytes
                    )
                    .to_string(),
                    kind: ConverterErrorKind::BlockFileCreation,
                });
            }

            info!("Creating block file of size {} bytes", size_bytes);
            let block_file =
                fs::File::create(block_file_out_path).map_err(|err| ConverterError {
                    message: format!(
                        "Failed creating block file {}. {:?}",
                        block_file_out_path.display(),
                        err
                    )
                    .to_string(),
                    kind: ConverterErrorKind::BlockFileCreation,
                })?;

            block_file
                .set_len(bytes_to_mb_ceil(size_bytes))
                .map_err(|err| ConverterError {
                    message: format!(
                        "Failed truncating block file {} to size {} bytes. {:?}",
                        block_file_out_path.display(),
                        size_bytes,
                        err
                    )
                    .to_string(),
                    kind: ConverterErrorKind::BlockFileCreation,
                })
        }

        async fn populate_block_file(
            client_fs_archive: &mut Archive<File>,
            user_config: &UserConfig,
            block_file_path: &Path,
            mount_path: &Path,
            nvidia_driver_capabilities: Option<&[String]>,
        ) -> Result<()> {
            // Create an ext4 file system inside file above
            run_subprocess0("mkfs.ext4", &[&block_file_path]).await?;

            // Mount the filesystem on the block file read-write (without dm-verity).
            // Block file will be automatically ummounted after this variable goes out of scope because we use `into_unmount_drop`.
            let _mount = Mount::builder()
                .explicit_loopback()
                .fstype("ext4")
                .mount(block_file_path, mount_path)
                .map(|e| e.into_unmount_drop(UnmountFlags::DETACH))
                .map_err(|err| ConverterError {
                    message: format!(
                        "Failed mounting block file {} into {}. {:?}.",
                        block_file_path.display(),
                        mount_path.display(),
                        err
                    ),
                    kind: ConverterErrorKind::BlockFileCreation,
                })?;

            // Populate the block file with the contents of the client image
            info!("Extracting client file system into the block file...");
            client_fs_archive
                .unpack_preserve_permissions(mount_path)
                .map_err(|message| ConverterError {
                    message,
                    kind: ConverterErrorKind::BlockFileFull,
                })?;

            GenericEnclaveImageBuilder::copy_nvidia_driver_payload(
                nvidia_driver_capabilities,
                mount_path,
            )?;

            // Make the current user the owner of the root of the filesystem on the block
            // device. This is just so we can write files to it with our own user id and not as root.
            let current_user = Uid::effective();

            chown(mount_path, Some(current_user), None).map_err(|err| ConverterError {
                message: format!(
                    "Failed changing owner of the path {} to {}. {:?}",
                    mount_path.display(),
                    current_user,
                    err
                )
                .to_string(),
                kind: ConverterErrorKind::BlockFileCreation,
            })?;

            GenericEnclaveImageBuilder::check_path_exists(user_config, mount_path)?;

            Ok(())
        }

        let mut client_fs_tar = self
            .export_image_file_system(docker_util, &self.dir.path().join("fs.tar"))
            .await?;

        let nvidia_driver_payload_size =
            Self::selected_nvidia_driver_payload_size(nvidia_driver_capabilities)?;
        if nvidia_driver_payload_size > 0 {
            info!(
                "Selected NVIDIA driver payload size is {} MiB",
                nvidia_driver_payload_size / MEGA_BYTE
            );
        }

        let mut size = client_fs_tar.size().map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::BlockFileCreation,
        })? + nvidia_driver_payload_size;
        let mut archive = client_fs_tar;

        // We retry image extraction below with a bigger block file size on every iteration
        // as it's hard to precisely compute the size required to describe all entities in the file system.
        // The total size includes file and directory metadata which varies based on the number of directories and files present in the client image.
        loop {
            size = (size as f64 * Self::BLOCK_FILE_SIZE_MULTIPLIER_INCREASE) as u64;
            archive = archive.rewind().map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::BlockFileCreation,
            })?;

            create_block_file(self.dir.path(), block_file_out_path, size).await?;

            match populate_block_file(
                &mut archive,
                user_config,
                block_file_out_path,
                mount_dir,
                nvidia_driver_capabilities,
            )
            .await
            {
                Err(ConverterError {
                    kind: ConverterErrorKind::BlockFileFull,
                    ..
                }) => {}
                Err(err) => return Err(err),
                _ => break,
            }
        }

        // Note that we're using the same file to contain the filesystem and the
        // filesystem hashes. That's why `block_file_out_as_str` is on the command line here twice.
        // The first time it's the filesystem block file. The second time it's the
        // device to use for the hashes. With --hash-offset, we're placing the hashes
        // in the same file, after the filesystem data.
        let hash_offset = bytes_to_mb_ceil(size);
        let block_file_out_as_str = path_as_str(block_file_out_path)?;
        let result = run_subprocess0(
            "veritysetup",
            &[
                "--hash-offset",
                &hash_offset.to_string(),
                "format",
                &block_file_out_as_str,
                &block_file_out_as_str,
            ],
        )
        .await?;

        FileSystemConfig::new(&result, hash_offset).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::BlockFileCreation,
        })
    }

    fn selected_nvidia_driver_payload_size(
        nvidia_driver_capabilities: Option<&[String]>,
    ) -> Result<u64> {
        let Some(capabilities) = nvidia_driver_capabilities else {
            return Ok(0);
        };

        if capabilities.is_empty() {
            return Ok(0);
        }

        let payload_root = Path::new(NVIDIA_DRIVER_PAYLOAD_ROOT);
        if !payload_root.exists() {
            return Err(ConverterError {
                message: format!(
                    "NVIDIA driver payload root {} does not exist in the converter image",
                    payload_root.display()
                ),
                kind: ConverterErrorKind::BlockFileCreation,
            });
        }

        let mut size = 0;
        for capability in capabilities {
            Self::validate_nvidia_driver_capability(capability)?;
            let capability_root = payload_root.join(capability);
            size += Self::directory_size(&capability_root.join("lib"))?;
            size += Self::directory_size(&capability_root.join("bin"))?;
        }

        Ok(size)
    }

    fn copy_nvidia_driver_payload(
        nvidia_driver_capabilities: Option<&[String]>,
        mount_path: &Path,
    ) -> Result<()> {
        let Some(capabilities) = nvidia_driver_capabilities else {
            return Ok(());
        };

        if capabilities.is_empty() {
            return Ok(());
        }

        let payload_root = Path::new(NVIDIA_DRIVER_PAYLOAD_ROOT);
        if !payload_root.exists() {
            return Err(ConverterError {
                message: format!(
                    "NVIDIA driver payload root {} does not exist in the converter image",
                    payload_root.display()
                ),
                kind: ConverterErrorKind::BlockFileCreation,
            });
        }

        let target_root = mount_path.join(NVIDIA_DRIVER_TARGET_ROOT);
        let target_lib = mount_path.join(NVIDIA_DRIVER_TARGET_LIB);
        let target_bin = mount_path.join(NVIDIA_DRIVER_TARGET_BIN);

        fs::create_dir_all(&target_lib).map_err(|err| ConverterError {
            message: format!(
                "Failed creating NVIDIA driver library dir {}. {:?}",
                target_lib.display(),
                err
            ),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;
        fs::create_dir_all(&target_bin).map_err(|err| ConverterError {
            message: format!(
                "Failed creating NVIDIA driver binary dir {}. {:?}",
                target_bin.display(),
                err
            ),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        for capability in capabilities {
            Self::validate_nvidia_driver_capability(capability)?;
            let capability_root = payload_root.join(capability);

            Self::copy_directory_contents(&capability_root.join("lib"), &target_lib)?;
            Self::copy_directory_contents(&capability_root.join("bin"), &target_bin)?;
        }

        info!(
            "Copied NVIDIA driver payload capabilities {:?} into {}",
            capabilities,
            target_root.display()
        );

        Ok(())
    }

    fn validate_nvidia_driver_capability(capability: &str) -> Result<()> {
        match capability {
            "compute" | "utility" => Ok(()),
            other => Err(ConverterError {
                message: format!(
                    "Unsupported NVIDIA driver capability {}. Supported capabilities are compute and utility",
                    other
                ),
                kind: ConverterErrorKind::BadRequest,
            }),
        }
    }

    fn directory_size(path: &Path) -> Result<u64> {
        if !path.exists() {
            return Ok(0);
        }

        let mut size = 0;
        for entry in fs::read_dir(path).map_err(|err| ConverterError {
            message: format!("Failed reading directory {}. {:?}", path.display(), err),
            kind: ConverterErrorKind::BlockFileCreation,
        })? {
            let entry = entry.map_err(|err| ConverterError {
                message: format!(
                    "Failed reading directory entry in {}. {:?}",
                    path.display(),
                    err
                ),
                kind: ConverterErrorKind::BlockFileCreation,
            })?;
            let entry_path = entry.path();
            let metadata = fs::symlink_metadata(&entry_path).map_err(|err| ConverterError {
                message: format!("Failed stat for {}. {:?}", entry_path.display(), err),
                kind: ConverterErrorKind::BlockFileCreation,
            })?;

            if metadata.file_type().is_dir() {
                size += Self::directory_size(&entry_path)?;
            } else {
                size += metadata.len();
            }
        }

        Ok(size)
    }

    fn copy_directory_contents(from: &Path, to: &Path) -> Result<()> {
        if !from.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(from).map_err(|err| ConverterError {
            message: format!("Failed reading directory {}. {:?}", from.display(), err),
            kind: ConverterErrorKind::BlockFileCreation,
        })? {
            let entry = entry.map_err(|err| ConverterError {
                message: format!(
                    "Failed reading directory entry in {}. {:?}",
                    from.display(),
                    err
                ),
                kind: ConverterErrorKind::BlockFileCreation,
            })?;
            let entry_path = entry.path();
            let target_path = to.join(entry.file_name());

            Self::copy_path(&entry_path, &target_path)?;
        }

        Ok(())
    }

    fn copy_path(from: &Path, to: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(from).map_err(|err| ConverterError {
            message: format!("Failed stat for {}. {:?}", from.display(), err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        if metadata.file_type().is_dir() {
            fs::create_dir_all(to).map_err(|err| ConverterError {
                message: format!("Failed creating directory {}. {:?}", to.display(), err),
                kind: ConverterErrorKind::BlockFileCreation,
            })?;
            Self::copy_directory_contents(from, to)?;
            return Ok(());
        }

        Self::remove_existing_path(to)?;

        if metadata.file_type().is_symlink() {
            let link_target = fs::read_link(from).map_err(|err| ConverterError {
                message: format!("Failed reading symlink {}. {:?}", from.display(), err),
                kind: ConverterErrorKind::BlockFileCreation,
            })?;
            unix_fs::symlink(&link_target, to).map_err(|err| ConverterError {
                message: format!(
                    "Failed creating symlink {} -> {}. {:?}",
                    to.display(),
                    link_target.display(),
                    err
                ),
                kind: ConverterErrorKind::BlockFileCreation,
            })?;
            return Ok(());
        }

        fs::copy(from, to).map_err(|err| ConverterError {
            message: format!(
                "Failed copying NVIDIA driver file {} to {}. {:?}",
                from.display(),
                to.display(),
                err
            ),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;
        fs::set_permissions(to, metadata.permissions()).map_err(|err| ConverterError {
            message: format!("Failed setting permissions on {}. {:?}", to.display(), err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        Ok(())
    }

    fn remove_existing_path(path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
                    fs::remove_dir_all(path)
                } else {
                    fs::remove_file(path)
                }
                .map_err(|err| ConverterError {
                    message: format!(
                        "Failed removing existing path {}. {:?}",
                        path.display(),
                        err
                    ),
                    kind: ConverterErrorKind::BlockFileCreation,
                })?;
            }
            Err(err) if err.kind() == IoErrorKind::NotFound => {}
            Err(err) => {
                return Err(ConverterError {
                    message: format!("Failed stat for {}. {:?}", path.display(), err),
                    kind: ConverterErrorKind::BlockFileCreation,
                })
            }
        }

        Ok(())
    }

    pub(crate) fn check_path_exists(
        user_config: &UserConfig,
        block_file_out_path: &Path,
    ) -> Result<()> {
        fn check_path_exists0(
            path_to_check: &Path,
            block_file_out_path: &Path,
            object_name: &str,
        ) -> Result<()> {
            let path = if path_to_check.is_absolute() {
                path_to_check.strip_prefix("/").unwrap()
            } else {
                path_to_check
            };

            match path.parent() {
                // This match arm describes a path that contains a valid directory prefix
                // Paths that consist of a single file name like "key.pem" will also end up here with path = "" (empty string),
                // which describes a file inside a folder specified by block_file_out_path
                Some(path) if !block_file_out_path.join(path).exists() => Err(ConverterError {
                    message: format!(
                        "{} path: {} doesn't exist inside client image.",
                        object_name,
                        path.display()
                    )
                    .to_string(),
                    kind: ConverterErrorKind::BadRequest,
                }),
                // If a path doesn't have any parent() it means that it doesn't have any directory prefix and is invalid.
                // A simple example of said path would be just a "/" symbol or an empty string.
                None => Err(ConverterError {
                    message: format!(
                        "{} path: {} parent directory doesn't exist inside client image.",
                        object_name,
                        path.display()
                    )
                    .to_string(),
                    kind: ConverterErrorKind::BadRequest,
                }),
                // If path contains a valid directory prefix that exists within block_file_out_path we return Ok
                _ => Ok(()),
            }
        }

        match user_config.certificate_config.first() {
            Some(CertificateConfig {
                key_path: Some(key_path),
                cert_path: Some(cert_path),
                ..
            }) => {
                check_path_exists0(Path::new(&key_path), block_file_out_path, "key")?;
                check_path_exists0(Path::new(&cert_path), block_file_out_path, "certificate")
            }
            Some(CertificateConfig {
                key_path: Some(key_path),
                ..
            }) => check_path_exists0(Path::new(&key_path), block_file_out_path, "key"),
            Some(CertificateConfig {
                cert_path: Some(cert_path),
                ..
            }) => check_path_exists0(Path::new(&cert_path), block_file_out_path, "certificate"),
            _ => Ok(()),
        }
    }
}

pub(crate) trait ArchiveExtensions {
    /// Returns total size of unpacked entities inside an archive without unpacking the archive itself.
    /// # Mutability remarks
    /// Modifies the underlying data pointer when iterating over the entries.
    /// To work with archive object again you have to rewind the pointer to the beginning of the underlying data structure.
    fn size(&mut self) -> std::result::Result<u64, String>
    where
        Self: Sized;

    /// Unpacks the contents of the archive while preserving file permissions.
    /// Without it any unknown file ownerships will default to a user id of the user who runs the program.
    /// This will lead to a permission issues when said files are accessed in a `chroot` environment.
    /// # Mutability remarks
    /// Modifies the underlying data pointer when iterating over the entries.
    /// To work with archive object again you have to rewind the pointer to the beginning of the underlying data structure.
    fn unpack_preserve_permissions(
        &mut self,
        destination: &Path,
    ) -> std::result::Result<(), String>;

    /// Rewinds the underlying data pointer to point to the beginning of the underlying data structure of the archive.
    fn rewind(self) -> std::result::Result<Self, String>
    where
        Self: Sized;
}

#[derive(Default, Debug)]
pub(crate) struct ArchiveSize {
    pub total_file_size: u64,

    pub dir_count: u64,

    pub file_count: u64,
}

impl ArchiveSize {
    /// Set to a common choice for disk block size; just an estimate:
    const DIR_ENTRY_SIZE: u64 = 4096;
    /// Set to 1/4 a block size; just an estimate:
    const PER_FILE_METADATA: u64 = 4096 / 4;

    pub(crate) fn size_bytes(self) -> u64 {
        ArchiveSize::PER_FILE_METADATA * self.file_count
            + self.total_file_size
            + ArchiveSize::DIR_ENTRY_SIZE * self.dir_count
    }
}

impl Add for ArchiveSize {
    type Output = ArchiveSize;

    fn add(self, other: ArchiveSize) -> Self {
        ArchiveSize {
            total_file_size: self.total_file_size + other.total_file_size,
            dir_count: self.dir_count + other.dir_count,
            file_count: self.file_count + other.file_count,
        }
    }
}

impl<'a, R: 'a + Read> From<tar::Entry<'a, R>> for ArchiveSize {
    fn from(entry: tar::Entry<'a, R>) -> Self {
        let entry_type = entry.header().entry_type();
        let dir_count = entry_type.is_dir() as u64;
        let file_count = !entry_type.is_dir() as u64;

        ArchiveSize {
            total_file_size: entry.size(),
            dir_count,
            file_count,
        }
    }
}

impl<'a, R: 'a + Read> From<std::result::Result<tar::Entry<'a, R>, std::io::Error>>
    for ArchiveSize
{
    fn from(entry: std::result::Result<tar::Entry<'a, R>, std::io::Error>) -> Self {
        match entry {
            Ok(entry) => ArchiveSize::from(entry),
            Err(e) => {
                warn!(
                    "Error reading archive entry while computing size of the client image: {:?}, ignoring.",
                    e
                );
                ArchiveSize::default()
            }
        }
    }
}

impl<T> ArchiveExtensions for Archive<T>
where
    T: Read + Seek,
{
    fn size(&mut self) -> std::result::Result<u64, String> {
        let entries = self
            .entries_with_seek()
            .map_err(|err| format!("Cannot read exported file system archive. {:?}", err))?;

        let result = entries.fold(ArchiveSize::default(), |accm, e| {
            accm + ArchiveSize::from(e)
        });

        debug!("Archive size measurements are: {:?}", result);

        Ok(result.size_bytes())
    }

    fn unpack_preserve_permissions(
        &mut self,
        destination: &Path,
    ) -> std::result::Result<(), String> {
        self.set_preserve_permissions(true);
        self.set_preserve_ownerships(true);

        self.unpack(destination).map_err(|err| {
            format!(
                "Failed unpacking client fs archive {}. {:?}",
                destination.display(),
                err
            )
        })
    }

    fn rewind(self) -> std::result::Result<Self, String> {
        let mut archive_file = self.into_inner();

        archive_file
            .rewind()
            .map_err(|err| format!("Failed rewinding archive. {:?}", err))?;

        Ok(Archive::new(archive_file))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};
    use std::path::{Path, PathBuf};

    use api_model::converter::{CertIssuer, CertificateConfig, KeyType};
    use api_model::enclave::{User, UserConfig, UserProgramConfig, WorkingDir};
    use rand::RngCore;
    use tar::{Archive, Builder};
    use tempfile::{NamedTempFile, TempDir};

    use crate::image_builder::enclave::{
        ArchiveExtensions, ArchiveSize, GenericEnclaveImageBuilder,
    };

    #[test]
    fn archive_size_add_zero_correct_pass() {
        let a = ArchiveSize {
            total_file_size: 1,
            dir_count: 2,
            file_count: 3,
        };

        let b = ArchiveSize::default();
        let result = a + b;

        assert_eq!(result.total_file_size, 1);
        assert_eq!(result.dir_count, 2);
        assert_eq!(result.file_count, 3);
    }

    #[test]
    fn archive_size_add_correct_pass() {
        let a = ArchiveSize {
            total_file_size: 1,
            dir_count: 1,
            file_count: 1,
        };

        let b = ArchiveSize {
            total_file_size: 1,
            dir_count: 2,
            file_count: 3,
        };

        let result = a + b;

        assert_eq!(result.total_file_size, 2);
        assert_eq!(result.dir_count, 3);
        assert_eq!(result.file_count, 4);
    }

    #[test]
    fn empty_archive_correct_pass() {
        use ArchiveExtensions;

        let archive_file = NamedTempFile::new_in("/tmp").expect("Failed creating archive file");

        let mut builder = Builder::new(archive_file);
        builder.finish().expect("failed building archive");

        let file = builder.into_inner().expect("Failed unwrapping builder");

        let mut archive = Archive::new(file);
        let result = archive
            .size()
            .expect("Failed computing size of the archive");

        assert_eq!(result, 0)
    }

    #[test]
    fn dir_and_file_archive_correct_pass() {
        use ArchiveExtensions;

        let archive_file =
            NamedTempFile::new_in(Path::new("/tmp")).expect("Failed creating archive file");
        let mut data_file_a =
            NamedTempFile::new_in(Path::new("/tmp")).expect("Failed creating data file");

        let test_data = "Hello World";
        data_file_a
            .write_all(test_data.as_bytes())
            .expect("Failed writing test data");
        data_file_a.rewind().expect("Failed rewinding file");

        let mut builder = Builder::new(archive_file);
        builder
            .append_dir("test-dir-a", "/")
            .expect("Failed appending dir to archive");
        builder
            .append_file("test-dir-a/file_a.txt", data_file_a.as_file_mut())
            .expect("Failed appending path to archive");

        let mut file = builder.into_inner().expect("Failed unwrapping builder");
        file.rewind().expect("Failed rewinding file");

        let mut archive = Archive::new(file);

        let result = archive
            .size()
            .expect("Failed computing size of the archive");
        let reference = ArchiveSize {
            total_file_size: test_data.as_bytes().len() as u64,
            dir_count: 1,
            file_count: 1,
        };

        assert_eq!(result, reference.size_bytes())
    }

    fn user_config(key_path: Option<String>, cert_path: Option<String>) -> UserConfig {
        UserConfig {
            user_program_config: UserProgramConfig {
                entry_point: "".to_string(),
                arguments: vec![],
                working_dir: WorkingDir::from(""),
                user: User::from(""),
                group: User::from(""),
            },
            certificate_config: vec![CertificateConfig {
                issuer: CertIssuer::ManagerCa,
                subject: None,
                alt_names: vec![],
                key_type: KeyType::Rsa,
                key_param: None,
                key_path,
                cert_path,
                chain_path: None,
            }],
        }
    }

    fn no_certs_user_config() -> UserConfig {
        UserConfig {
            user_program_config: UserProgramConfig {
                entry_point: "".to_string(),
                arguments: vec![],
                working_dir: WorkingDir::from(""),
                user: User::from(""),
                group: User::from(""),
            },
            certificate_config: vec![],
        }
    }

    fn abs_non_existent_path() -> PathBuf {
        non_existent_path(Path::new("/path/to/some/file"))
    }

    fn relative_non_existent_path() -> PathBuf {
        non_existent_path(Path::new("path/to/some/file"))
    }

    fn non_existent_path(base_path: &Path) -> PathBuf {
        let mut rng = rand::thread_rng();
        let mut result = base_path.to_path_buf();

        while result.exists() {
            let random_number = rng.next_u32();
            result = base_path.join(random_number.to_string());
        }

        result
    }

    fn path_to_str(path: &Path) -> String {
        path.to_str().expect("path to str fail").to_string()
    }

    #[test]
    fn check_path_not_found_correct_path() {
        let abs_key_path = abs_non_existent_path();
        let abs_cert_path = abs_non_existent_path();
        let relative_key_path = relative_non_existent_path();
        let relative_cert_path = relative_non_existent_path();
        let no_file_path = Path::new("/");

        assert!(abs_cert_path.is_absolute());
        assert!(abs_cert_path.is_absolute());
        assert!(relative_key_path.is_relative());
        assert!(relative_cert_path.is_relative());

        let configs = vec![
            user_config(Some(path_to_str(&abs_key_path)), None),
            user_config(None, Some(path_to_str(&abs_cert_path))),
            user_config(
                Some(path_to_str(&abs_key_path)),
                Some(path_to_str(&abs_cert_path)),
            ),
            user_config(Some(path_to_str(&relative_key_path)), None),
            user_config(None, Some(path_to_str(&relative_cert_path))),
            user_config(
                Some(path_to_str(&relative_key_path)),
                Some(path_to_str(&relative_cert_path)),
            ),
            user_config(
                Some(path_to_str(&no_file_path)),
                Some(path_to_str(&no_file_path)),
            ),
            user_config(Some(String::new()), Some(String::new())),
        ];

        let block_file_valid_path = Path::new("/tmp");

        for config in &configs {
            assert!(
                GenericEnclaveImageBuilder::check_path_exists(config, block_file_valid_path)
                    .is_err(),
                "Config used: {:?}",
                config
            )
        }

        let block_file_invalid_path = abs_non_existent_path();

        for config in &configs {
            assert!(
                GenericEnclaveImageBuilder::check_path_exists(
                    config,
                    Path::new(&block_file_invalid_path)
                )
                .is_err(),
                "Config used: {:?}",
                config
            )
        }
    }

    #[test]
    fn check_path_empty_config_correct_path() {
        let configs = vec![user_config(None, None), no_certs_user_config()];

        for config in &configs {
            assert!(
                GenericEnclaveImageBuilder::check_path_exists(config, Path::new("/tmp")).is_ok()
            )
        }
    }

    #[test]
    fn check_path_found_correct_path() {
        let block_file_valid_path = Path::new("/tmp");
        let key_file_dir =
            TempDir::new_in(block_file_valid_path).expect("Failed creating key file dir");
        let cert_file_dir =
            TempDir::new_in(block_file_valid_path).expect("Failed creating cert file dir");

        let abs_key_path = {
            let result = key_file_dir
                .path()
                .strip_prefix("/tmp")
                .unwrap()
                .join("key.pem");
            Path::new("/").join(result)
        };
        let abs_cert_path = {
            let result = cert_file_dir
                .path()
                .strip_prefix("/tmp")
                .unwrap()
                .join("cert.pem");
            Path::new("/").join(result)
        };

        assert!(abs_key_path.is_absolute());
        assert!(abs_cert_path.is_absolute());

        let relative_key_path = key_file_dir
            .path()
            .strip_prefix("/tmp/")
            .unwrap()
            .join("key.pem");
        let relative_cert_path = cert_file_dir
            .path()
            .strip_prefix("/tmp/")
            .unwrap()
            .join("cert.pem");

        assert!(relative_key_path.is_relative());
        assert!(relative_cert_path.is_relative());

        let configs = vec![
            user_config(Some(path_to_str(&abs_key_path)), None),
            user_config(None, Some(path_to_str(&abs_cert_path))),
            user_config(
                Some(path_to_str(&abs_key_path)),
                Some(path_to_str(&abs_cert_path)),
            ),
            user_config(Some(path_to_str(&relative_key_path)), None),
            user_config(None, Some(path_to_str(&relative_cert_path))),
            user_config(
                Some(path_to_str(&relative_key_path)),
                Some(path_to_str(&relative_cert_path)),
            ),
        ];

        for config in &configs {
            assert!(
                GenericEnclaveImageBuilder::check_path_exists(config, block_file_valid_path)
                    .is_ok(),
                "Config used: {:?}",
                config
            )
        }
    }
}
