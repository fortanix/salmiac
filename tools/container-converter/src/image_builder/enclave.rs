/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use api_model::enclave::{EnclaveManifest, FileSystemConfig, UserConfig};
use api_model::converter::{ConverterOptions, CertificateConfig};
use docker_image_reference::Reference as DockerReference;
use log::{info, debug, warn};
use nix::unistd::chown;
use nix::unistd::Uid;
use nix::sys::statfs::statfs;
use rand::distributions::{Alphanumeric, DistString};
use serde::Deserialize;
use sys_mount::{Mount, Unmount, UnmountFlags};
use tar::Archive;
use tempfile::TempDir;

use crate::docker::DockerUtil;
use crate::file::{BuildContext, DockerCopyArgs, DockerFile, Resource};
use crate::image::{ImageKind, ImageToClean, ImageWithDetails};
use crate::image_builder::{path_as_str, rust_log_env_var, INSTALLATION_DIR, MEGA_BYTE};
use crate::{run_subprocess, ConverterError, ConverterErrorKind, Result};

use std::ffi::OsStr;
use std::fmt::Debug;
use std::fs;
use std::fs::File;
use std::io::{Seek, Read};
use std::path::Path;
use std::sync::mpsc::Sender;
use std::ops::Add;

#[derive(Deserialize)]
pub(crate) struct NitroEnclaveMeasurements {
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

pub(crate) async fn create_nitro_image(image: &DockerReference<'_>, output_file: &Path) -> Result<NitroEnclaveMeasurements> {
    let output = output_file.to_str().ok_or(ConverterError {
        message: format!("Failed to cast path {:?} to string", output_file),
        kind: ConverterErrorKind::NitroFileCreation,
    })?;

    let image_as_str = image.to_string();

    let nitro_cli_args = ["build-enclave", "--docker-uri", &image_as_str, "--output-file", output];

    let process_output = run_subprocess("nitro-cli", &nitro_cli_args)
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::NitroFileCreation,
        })?;

    serde_json::from_str::<NitroEnclaveMeasurements>(&process_output).map_err(|err| ConverterError {
        message: format!("Bad measurements. {:?}", err),
        kind: ConverterErrorKind::NitroFileCreation,
    })
}

pub(crate) fn get_image_env(input_image: &ImageWithDetails<'_>, converter_options: &ConverterOptions) -> Vec<String> {
    let mut result = input_image.details.config.env.as_ref().map(|e| e.clone()).unwrap_or(vec![]);

    // Docker `ENV` assigns environment variables by the order of definition, thus making
    // latest definition of the same variable override previous definition.
    // We exploit this logic to override variables from the `input_image` with the values from `conversion_request`
    // by adding all `conversion_request` variables to the end of `env_vars` vector.
    for request_env in &converter_options.env_vars {
        result.push(request_env.clone());
    }
    result
}

pub(crate) struct EnclaveSettings {
    user_name: String,

    pub(crate) env_vars: Vec<String>,

    is_debug: bool,

    enable_overlay_filesystem_persistence: bool
}

impl EnclaveSettings {
    pub(crate) fn new(input_image: &ImageWithDetails<'_>, converter_options: &ConverterOptions) -> Self {
        EnclaveSettings {
            user_name: input_image.details.config.user.clone(),
            env_vars: vec![rust_log_env_var("enclave")],
            is_debug: converter_options.debug.unwrap_or(false),
            enable_overlay_filesystem_persistence: converter_options.enable_overlay_filesystem_persistence.unwrap_or(false)
        }
    }
}

pub(crate) struct EnclaveImageBuilder<'a> {
    pub(crate) client_image_reference: &'a DockerReference<'a>,

    pub(crate) dir: &'a TempDir,

    pub(crate) enclave_base_image: &'a DockerReference<'a>,
}

impl<'a> EnclaveImageBuilder<'a> {
    pub const ENCLAVE_FILE_NAME: &'static str = "enclave.eif";

    const DEFAULT_ENCLAVE_SETTINGS_FILE: &'static str = "enclave-settings.json";

    const BLOCK_FILE_MOUNT_DIR: &'static str = "block-file-mount";

    pub const BLOCK_FILE_OUT: &'static str = "Blockfile.ext4";

    const BLOCK_FILE_SIZE_MULTIPLIER_INCREASE: f64 = 1.5; // 50% increase of the block file size

    const IMAGE_BUILD_DEPENDENCIES: &'static [Resource<'static>] = &[
        Resource {
            name: "enclave",
            data: include_bytes!("../resources/enclave/enclave"),
            is_executable: true,
        },
        Resource {
            name: "enclave-startup",
            data: include_bytes!("../resources/enclave/enclave-startup"),
            is_executable: true,
        },
    ];

    const IMAGE_COPY_DEPENDENCIES: &'static [&'static str] = &["enclave", "enclave-settings.json", "enclave-startup"];

    pub(crate) async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        enclave_settings: EnclaveSettings,
        user_config: UserConfig,
        env_vars: Vec<String>,
        images_to_clean_snd: Sender<ImageToClean>,
    ) -> Result<NitroEnclaveMeasurements> {
        let is_debug = enclave_settings.is_debug;
        let enable_overlay_filesystem_persistence = enclave_settings.enable_overlay_filesystem_persistence;

        let build_context = BuildContext::new(&self.dir.path()).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        self.create_requisites(enclave_settings, &build_context)
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        let file_system_config = self.create_block_file(docker_util, &user_config).await?;
        info!("Client FS Block file has been created.");

        let enclave_manifest = EnclaveManifest {
            user_config,
            file_system_config,
            is_debug,
            env_vars,
            enable_overlay_filesystem_persistence
        };

        self.create_manifest_file(enclave_manifest, &build_context)?;

        info!("Enclave build prerequisites have been created!");

        let result_image_raw = if is_debug {
            self.enclave_debug_image()
        } else {
            self.enclave_image()
        };

        let result_reference = if is_debug {
            let reference = DockerReference::from_str(&result_image_raw).map_err(|message| ConverterError {
                message: format!("Failed to create enclave image reference. {:?}", message),
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

            self.create_debug_client_image(&self.enclave_base_image, reference, docker_util)
                .await
                .map(|e| e.reference)?
        } else {
            DockerReference::from_str(&result_image_raw).map_err(|message| ConverterError {
                message: format!("Failed to create enclave image reference. {:?}", message),
                kind: ConverterErrorKind::RequisitesCreation,
            })?
        };

        let build_context_archive_file = build_context
            .package_into_archive(&self.dir.path().join("enclave-build-context.tar"))
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        // This image is made temporary because it is only used by nitro-cli to create an `.eif` file.
        // After nitro-cli finishes we can safely reclaim it.
        let result = docker_util
            .create_image_from_archive(result_reference, build_context_archive_file)
            .await
            .map(|e| e.make_temporary(ImageKind::Intermediate, images_to_clean_snd))
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::EnclaveImageCreation,
            })?;

        let nitro_measurements = {
            let nitro_image_path = &self.dir.path().join(EnclaveImageBuilder::ENCLAVE_FILE_NAME);

            create_nitro_image(&result.image.reference, &nitro_image_path).await?
        };

        info!("Nitro image has been created!");

        Ok(nitro_measurements)
    }

    async fn create_debug_client_image<'b>(
        &self,
        debug_enclave_base: &DockerReference<'_>,
        result_reference: DockerReference<'b>,
        docker_util: &dyn DockerUtil,
    ) -> Result<ImageWithDetails<'b>> {
        info!("Creating debug enclave image");

        let build_context = BuildContext::new(&self.dir.path()).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        build_context
            .create_docker_file(&DockerFile::from(debug_enclave_base.to_string()))
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        let build_context_archive_file = build_context
            .package_into_archive(&self.dir.path().join("enclave-debug-build-context.tar"))
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        docker_util
            .create_image_from_archive(result_reference, build_context_archive_file)
            .await
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::EnclaveImageCreation,
            })
    }

    pub(crate) async fn export_image_file_system(
        &self,
        docker_util: &dyn DockerUtil,
        archive_path: &Path,
    ) -> Result<Archive<File>> {
        let mut archive_file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&archive_path)
            .map_err(|err| ConverterError {
                message: format!("Failed creating image fs archive at {}. {:?}", archive_path.display(), err),
                kind: ConverterErrorKind::ImageFileSystemExport,
            })?;

        docker_util
            .export_image_file_system(&self.client_image_reference, &mut archive_file)
            .await
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::ImageFileSystemExport,
            })?;

        archive_file.rewind().map_err(|err| ConverterError {
            message: format!("Failed seek in image fs archive at {}. {:?}", archive_path.display(), err),
            kind: ConverterErrorKind::ImageFileSystemExport,
        })?;

        Ok(Archive::new(archive_file))
    }

    fn create_manifest_file(&self, enclave_manifest: EnclaveManifest, build_context: &BuildContext) -> Result<()> {
        let data = serde_json::to_vec(&enclave_manifest).map_err(|err| ConverterError {
            message: format!("Failed serializing enclave settings file. {:?}", err),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        let resource = Resource {
            name: "enclave-settings.json",
            data: &data,
            is_executable: false,
        };

        build_context.create_resource(resource).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })
    }

    async fn create_block_file(&self, docker_util: &dyn DockerUtil, user_config: &UserConfig) -> Result<FileSystemConfig> {
        let block_file_mount_dir = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_MOUNT_DIR);
        let block_file_out = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_OUT);

        fs::create_dir(&block_file_mount_dir).map_err(|err| ConverterError {
            message: format!("Failed creating dir {}. {:?}", block_file_mount_dir.display(), err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        self.create_block_file0(&block_file_mount_dir, &block_file_out, user_config, docker_util)
            .await
    }

    fn enclave_image(&self) -> String {
        self.retag_client_image(&Alphanumeric.sample_string(&mut rand::thread_rng(), 16))
    }

    fn enclave_debug_image(&self) -> String {
        self.retag_client_image("debug")
    }

    fn retag_client_image(&self, tag: &str) -> String {
        let new_tag = self
            .client_image_reference
            .tag()
            .map(|e| e.to_string() + "-" + tag)
            .unwrap_or("enclave".to_string());

        self.client_image_reference.name().to_string() + ":" + &new_tag
    }

    fn create_requisites(
        &self,
        enclave_settings: EnclaveSettings,
        build_context: &BuildContext,
    ) -> std::result::Result<(), String> {
        let docker_file = self.docker_file_contents(enclave_settings);

        build_context.create_docker_file(&docker_file)?;

        build_context.create_resources(EnclaveImageBuilder::IMAGE_BUILD_DEPENDENCIES)?;

        Ok(())
    }

    fn docker_file_contents(&self, mut enclave_settings: EnclaveSettings) -> DockerFile {
        let install_dir_path = Path::new(INSTALLATION_DIR);

        let items = EnclaveImageBuilder::IMAGE_COPY_DEPENDENCIES
            .iter()
            .map(|e| e.to_string())
            .collect();

        let add = DockerCopyArgs {
            items,
            destination: INSTALLATION_DIR.to_string() + "/",
        };

        let run_enclave_cmd = {
            let enclave_bin = install_dir_path.join("enclave");

            let enclave_settings_file = install_dir_path.join(EnclaveImageBuilder::DEFAULT_ENCLAVE_SETTINGS_FILE);

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
        };

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
    ) -> Result<FileSystemConfig> {
        async fn run_subprocess0<S: AsRef<OsStr> + Debug, A: AsRef<OsStr> + Debug>(
            subprocess_path: S,
            args: &[A],
        ) -> Result<String> {
            run_subprocess(subprocess_path, args).await.map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::BlockFileCreation,
            })
        }

        async fn get_available_disc_space(block_file_dir: &Path) -> Result<u64> {
            statfs(block_file_dir)
                .map(|e| e.block_size() as u64 * e.blocks_available())
                .map_err(|err| ConverterError {
                    message: format!("Failure retrieving available disc space using `statfs` for path {}. {:?}", block_file_dir.display(), err).to_string(),
                    kind: ConverterErrorKind::BlockFileCreation,
                })
        }

        async fn create_block_file(working_dir: &Path, block_file_out_path: &Path, size_mb: u64) -> Result<()> {
            let available_disc_space = get_available_disc_space(working_dir).await?;

            if available_disc_space < size_mb {
                return Err(ConverterError {
                    message: format!(
                        "Available disk space: {} Required disk space: {}",
                        available_disc_space, size_mb
                    )
                        .to_string(),
                    kind: ConverterErrorKind::BlockFileCreation,
                });
            }

            info!("Creating block file of size {}MB", size_mb);
            let block_file = fs::File::create(block_file_out_path).map_err(|err| ConverterError {
                message: format!("Failed creating block file {}. {:?}", block_file_out_path.display(), err).to_string(),
                kind: ConverterErrorKind::BlockFileCreation,
            })?;

            block_file
                .set_len(size_mb * MEGA_BYTE)
                .map_err(|err| ConverterError {
                    message: format!(
                        "Failed truncating block file {} to size {}. {:?}",
                        block_file_out_path.display(),
                        size_mb,
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
        ) -> Result<()> {
            // Create an ext4 file system inside file above
            run_subprocess0("mkfs.ext4", &[&block_file_path]).await?;

            // Mount the filesystem on the block file read-write (without dm-verity).
            // Block file will be automatically ummounted after this variable goes out of scope because we use `into_unmount_drop`.
            let _mount = Mount::builder()
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

            EnclaveImageBuilder::check_path_exists(user_config, mount_path)?;

            Ok(())
        }

        let mut client_fs_tar = self
            .export_image_file_system(docker_util, &self.dir.path().join("fs.tar"))
            .await?;

        let size = client_fs_tar.size().map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        let mut size_mb_up = (size / MEGA_BYTE) as u64;
        let mut archive = client_fs_tar;

        // We retry image extraction below with a bigger block file size on every iteration
        // as it's hard to precisely compute the size required to describe all entities in the file system.
        // The total size includes file and directory metadata which varies based on the number of directories and files present in the client image.
        loop {
            size_mb_up = (size_mb_up as f64 * EnclaveImageBuilder::BLOCK_FILE_SIZE_MULTIPLIER_INCREASE) as u64;
            archive = archive.rewind().map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::BlockFileCreation,
            })?;

            create_block_file(self.dir.path(), block_file_out_path, size_mb_up).await?;

            match populate_block_file(&mut archive, user_config, block_file_out_path, mount_dir).await {
                Err(ConverterError { kind: ConverterErrorKind::BlockFileFull, .. }) => {

                }
                Err(err) => {
                    return Err(err)
                }
                _ => {
                    break
                }
            }
        }

        // Note that we're using the same file to contain the filesystem and the
        // filesystem hashes. That's why `block_file_out_as_str` is on the command line here twice.
        // The first time it's the filesystem block file. The second time it's the
        // device to use for the hashes. With --hash-offset, we're placing the hashes
        // in the same file, after the filesystem data.
        let hash_offset = size_mb_up * MEGA_BYTE;
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

    fn check_path_exists(user_config: &UserConfig, block_file_out_path: &Path) -> Result<()> {
        fn check_path_exists0(path_to_check: &Path, block_file_out_path: &Path, object_name: &str) -> Result<()> {
            let path = if path_to_check.is_absolute() {
                path_to_check.strip_prefix("/").unwrap()
            } else {
                path_to_check
            };

            match path.parent() {
                // This match arm describes a path that contains a valid directory prefix
                // Paths that consist of a single file name like "key.pem" will also end up here with path = "" (empty string),
                // which describes a file inside a folder specified by block_file_out_path
                Some(path) if !block_file_out_path.join(path).exists() => {
                    Err(ConverterError {
                        message: format!("{} path: {} doesn't exist inside client image.", object_name, path.display()).to_string(),
                        kind: ConverterErrorKind::BadRequest,
                    })
                }
                // If a path doesn't have any parent() it means that it doesn't have any directory prefix and is invalid.
                // A simple example of said path would be just a "/" symbol or an empty string.
                None => {
                    Err(ConverterError {
                        message: format!("{} path: {} parent directory doesn't exist inside client image.", object_name, path.display()).to_string(),
                        kind: ConverterErrorKind::BadRequest,
                    })
                }
                // If path contains a valid directory prefix that exists within block_file_out_path we return Ok
                _ => {
                    Ok(())
                }
            }
        }

        match user_config.certificate_config.first() {
            Some(CertificateConfig { key_path: Some(key_path), cert_path: Some(cert_path), ..}) => {
                check_path_exists0(Path::new(&key_path), block_file_out_path, "key")?;
                check_path_exists0(Path::new(&cert_path), block_file_out_path, "certificate")
            }
            Some(CertificateConfig { key_path: Some(key_path), ..}) => {
                check_path_exists0(Path::new(&key_path), block_file_out_path, "key")
            }
            Some(CertificateConfig { cert_path: Some(cert_path), ..}) => {
                check_path_exists0(Path::new(&cert_path), block_file_out_path, "certificate")
            }
            _ => {
                Ok(())
            }
        }
    }
}

trait ArchiveExtensions {
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
    fn unpack_preserve_permissions(&mut self, destination: &Path) -> std::result::Result<(), String>;

    /// Rewinds the underlying data pointer to point to the beginning of the underlying data structure of the archive.
    fn rewind(self) -> std::result::Result<Self, String>
    where
        Self: Sized;
}

#[derive(Default, Debug)]
struct ArchiveSize {
    pub total_file_size: u64,

    pub dir_count: u64,

    pub file_count: u64
}

impl ArchiveSize {
    /// Set to a common choice for disk block size; just an estimate:
    const DIR_ENTRY_SIZE: u64 = 4096;
    /// Set to 1/4 a block size; just an estimate:
    const PER_FILE_METADATA: u64 = 4096/4;

    fn size_bytes(self) -> u64 {
        ArchiveSize::PER_FILE_METADATA * self.file_count + self.total_file_size + ArchiveSize::DIR_ENTRY_SIZE * self.dir_count
    }
}

impl Add for ArchiveSize {
    type Output = ArchiveSize;

    fn add(self, other: ArchiveSize) -> Self {
        ArchiveSize {
            total_file_size: self.total_file_size + other.total_file_size,
            dir_count: self.dir_count + other.dir_count,
            file_count: self.file_count + other.file_count
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
            file_count
        }
    }
}

impl<'a, R: 'a + Read> From<std::result::Result<tar::Entry<'a, R>, std::io::Error>> for ArchiveSize {
    fn from(entry: std::result::Result<tar::Entry<'a, R>, std::io::Error>) -> Self {
        match entry {
            Ok(entry) => {
                ArchiveSize::from(entry)
            },
            Err(e) => {
                warn!("Error reading archive entry while computing size of the client image: {:?}, ignoring.", e);
                ArchiveSize::default()
            }
        }
    }
}

impl<T> ArchiveExtensions for Archive<T> where T: Read + Seek  {
    fn size(&mut self) -> std::result::Result<u64, String> {
        let entries = self
            .entries_with_seek()
            .map_err(|err| format!("Cannot read exported file system archive. {:?}", err))?;

        let result = entries.fold(ArchiveSize::default(), |accm,  e| accm + ArchiveSize::from(e));

        debug!("Archive size measurements are: {:?}", result);

        Ok(result.size_bytes())
    }

    fn unpack_preserve_permissions(&mut self, destination: &Path) -> std::result::Result<(), String> {
        self.set_preserve_permissions(true);
        self.set_preserve_ownerships(true);

        self.unpack(destination)
            .map_err(|err| format!("Failed unpacking client fs archive {}. {:?}", destination.display(), err))
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
    use crate::image_builder::enclave::{ArchiveSize, ArchiveExtensions};
    use tar::{Archive, Builder};
    use tempfile::{NamedTempFile, TempDir};
    use std::path::{Path, PathBuf};
    use std::io::{Write, Seek};
    use crate::image_builder::enclave::EnclaveImageBuilder;
    use api_model::enclave::{UserConfig, UserProgramConfig, WorkingDir, User};
    use rand::RngCore;
    use api_model::converter::{CertificateConfig, CertIssuer, KeyType};

    #[test]
    fn archive_size_add_zero_correct_pass() {
        let a = ArchiveSize {
            total_file_size: 1,
            dir_count: 2,
            file_count: 3
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
            file_count: 1
        };

        let b = ArchiveSize {
            total_file_size: 1,
            dir_count: 2,
            file_count: 3
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
        let result = archive.size().expect("Failed computing size of the archive");

        assert_eq!(result, 0)
    }

    #[test]
    fn dir_and_file_archive_correct_pass() {
        use ArchiveExtensions;

        let archive_file = NamedTempFile::new_in(Path::new("/tmp")).expect("Failed creating archive file");
        let mut data_file_a = NamedTempFile::new_in(Path::new("/tmp")).expect("Failed creating data file");

        let test_data = "Hello World";
        data_file_a.write_all(test_data.as_bytes()).expect("Failed writing test data");
        data_file_a.rewind().expect("Failed rewinding file");

        let mut builder = Builder::new(archive_file);
        builder.append_dir("test-dir-a", "/").expect("Failed appending dir to archive");
        builder.append_file("test-dir-a/file_a.txt", data_file_a.as_file_mut()).expect("Failed appending path to archive");

        let mut file = builder.into_inner().expect("Failed unwrapping builder");
        file.rewind().expect("Failed rewinding file");

        let mut archive = Archive::new(file);

        let result = archive.size().expect("Failed computing size of the archive");
        let reference = ArchiveSize {
            total_file_size: test_data.as_bytes().len() as u64,
            dir_count: 1,
            file_count: 1
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
        path.to_str()
            .expect("path to str fail")
            .to_string()
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
            user_config(Some(path_to_str(&abs_key_path)), Some(path_to_str(&abs_cert_path))),
            user_config(Some(path_to_str(&relative_key_path)), None),
            user_config(None, Some(path_to_str(&relative_cert_path))),
            user_config(Some(path_to_str(&relative_key_path)), Some(path_to_str(&relative_cert_path))),
            user_config(Some(path_to_str(&no_file_path)), Some(path_to_str(&no_file_path))),
            user_config(Some(String::new()), Some(String::new()))
        ];

        let block_file_valid_path = Path::new("/tmp");

        for config in &configs {
            assert!(EnclaveImageBuilder::check_path_exists(config, block_file_valid_path).is_err(), "Config used: {:?}", config)
        }

        let block_file_invalid_path = abs_non_existent_path();

        for config in &configs {
            assert!(EnclaveImageBuilder::check_path_exists(config, Path::new(&block_file_invalid_path)).is_err(), "Config used: {:?}", config)
        }
    }

    #[test]
    fn check_path_empty_config_correct_path() {
        let configs = vec![
            user_config(None, None),
            no_certs_user_config()
        ];

        for config in &configs {
            assert!(EnclaveImageBuilder::check_path_exists(config, Path::new("/tmp")).is_ok())
        }
    }

    #[test]
    fn check_path_found_correct_path() {
        let block_file_valid_path = Path::new("/tmp");
        let key_file_dir = TempDir::new_in(block_file_valid_path).expect("Failed creating key file dir");
        let cert_file_dir = TempDir::new_in(block_file_valid_path).expect("Failed creating cert file dir");

        let abs_key_path = {
            let result = key_file_dir.path().strip_prefix("/tmp").unwrap().join("key.pem");
            Path::new("/").join(result)
        };
        let abs_cert_path = {
            let result = cert_file_dir.path().strip_prefix("/tmp").unwrap().join("cert.pem");
            Path::new("/").join(result)
        };

        assert!(abs_key_path.is_absolute());
        assert!(abs_cert_path.is_absolute());

        let relative_key_path = key_file_dir.path().strip_prefix("/tmp/").unwrap().join("key.pem");
        let relative_cert_path = cert_file_dir.path().strip_prefix("/tmp/").unwrap().join("cert.pem");

        assert!(relative_key_path.is_relative());
        assert!(relative_cert_path.is_relative());

        let configs = vec![
            user_config(Some(path_to_str(&abs_key_path)), None),
            user_config(None, Some(path_to_str(&abs_cert_path))),
            user_config(Some(path_to_str(&abs_key_path)), Some(path_to_str(&abs_cert_path))),
            user_config(Some(path_to_str(&relative_key_path)), None),
            user_config(None, Some(path_to_str(&relative_cert_path))),
            user_config(Some(path_to_str(&relative_key_path)), Some(path_to_str(&relative_cert_path)))
        ];

        for config in &configs {
            assert!(EnclaveImageBuilder::check_path_exists(config, block_file_valid_path).is_ok(), "Config used: {:?}", config)
        }
    }
}
