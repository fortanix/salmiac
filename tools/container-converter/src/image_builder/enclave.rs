use api_model::shared::{EnclaveManifest, FileSystemConfig, UserConfig};
use api_model::ConverterOptions;
use docker_image_reference::Reference as DockerReference;
use log::info;
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
use std::io::Seek;
use std::path::Path;
use std::sync::mpsc::Sender;

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
}

impl EnclaveSettings {
    pub(crate) fn new(input_image: &ImageWithDetails<'_>, converter_options: &ConverterOptions) -> Self {
        EnclaveSettings {
            user_name: input_image.details.config.user.clone(),
            env_vars: vec![rust_log_env_var("enclave")],
            is_debug: converter_options.debug.unwrap_or(false),
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

    const BLOCK_FILE_SIZE_MULTIPLIER: f64 = 2.0;

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

        let build_context = BuildContext::new(&self.dir.path()).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        self.create_requisites(enclave_settings, &build_context)
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        let file_system_config = self.create_block_file(docker_util).await?;
        info!("Client FS Block file has been created.");

        let enclave_manifest = EnclaveManifest {
            user_config,
            file_system_config,
            is_debug,
            env_vars,
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

    async fn create_block_file(&self, docker_util: &dyn DockerUtil) -> Result<FileSystemConfig> {
        let block_file_mount_dir = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_MOUNT_DIR);
        let block_file_out = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_OUT);

        fs::create_dir(&block_file_mount_dir).map_err(|err| ConverterError {
            message: format!("Failed creating dir {}. {:?}", block_file_mount_dir.display(), err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        self.create_block_file0(&block_file_mount_dir, &block_file_out, docker_util)
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
            cmd: Some(run_enclave_cmd),
            entrypoint: None,
        }
    }

    async fn create_block_file0(
        &self,
        mount_dir: &Path,
        block_file_out_path: &Path,
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

        fn create_block_file(block_file_out_path: &Path, size_mb: u64) -> Result<()> {
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
            client_fs_archive: Archive<File>,
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
                    kind: ConverterErrorKind::BlockFileCreation,
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
            })
        }

        let client_fs_tar = self
            .export_image_file_system(docker_util, &self.dir.path().join("fs.tar"))
            .await?;

        let (rewinded_client_fs_tar, size_mb) = client_fs_tar.size().map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        info!("Client file system size is {}MB", size_mb);

        let size_mb_up = (size_mb as f64 * EnclaveImageBuilder::BLOCK_FILE_SIZE_MULTIPLIER) as u64;

        let available_disc_space = get_available_disc_space(self.dir.path()).await?;

        if available_disc_space < size_mb_up {
            return Err(ConverterError {
                message: format!(
                    "Available disk space: {} Required disk space: {}",
                    available_disc_space, size_mb_up
                )
                .to_string(),
                kind: ConverterErrorKind::BlockFileCreation,
            });
        }

        create_block_file(block_file_out_path, size_mb_up)?;

        populate_block_file(rewinded_client_fs_tar, block_file_out_path, mount_dir).await?;

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
}

trait ArchiveExtensions {
    /// Returns total size of unpacked entities inside an archive without unpacking the archive itself.
    fn size(self) -> std::result::Result<(Self, u64), String>
    where
        Self: Sized;

    /// Unpacks the contents of the archive while preserving file permissions.
    /// Without it any unknown file ownerships will default to a user id of the user who runs the program.
    /// This will lead to a permission issues when said files are accessed in a `chroot` environment.
    fn unpack_preserve_permissions(self, destination: &Path) -> std::result::Result<(), String>;
}

impl ArchiveExtensions for Archive<File> {
    fn size(mut self) -> std::result::Result<(Self, u64), String> {
        let entries = self
            .entries_with_seek()
            .map_err(|err| format!("Cannot read exported file system archive. {:?}", err))?;

        let result = entries.fold(0 as u64, |acc, e| {
            let entry_size = e.map(|ee| ee.size()).unwrap_or(0);

            acc + entry_size
        }) / MEGA_BYTE;

        // Iterating over `entries` also moves file pointer inside `Archive<File>`.
        // To preserve the archive state from a caller perspective we have to rewind the file pointer and recreate the `Archive<File>` object.
        let mut archive_file = self.into_inner();

        archive_file
            .rewind()
            .map_err(|err| format!("Failed rewinding fs archive file. {:?}", err))?;

        Ok((Archive::new(archive_file), result))
    }

    fn unpack_preserve_permissions(mut self, destination: &Path) -> std::result::Result<(), String> {
        self.set_preserve_permissions(true);
        self.set_preserve_ownerships(true);

        self.unpack(destination)
            .map_err(|err| format!("Failed unpacking client fs archive {}. {:?}", destination.display(), err))
    }
}
