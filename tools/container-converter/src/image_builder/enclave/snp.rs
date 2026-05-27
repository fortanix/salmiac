/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io::{Cursor, Error as IoError, ErrorKind as IoErrorKind, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::{env, fs};

use api_model::enclave::{EnclaveManifest, UserConfig};
use api_model::snp::{SNPEnclavesConversionRequestOptions, SNPEnclavesMeasurements};
use fortanix_vme_initramfs::{FsTree, Initramfs};
use log::{info, warn};
use nix::sys::stat::SFlag;
use tar::{Archive, EntryType};

use crate::image_builder::enclave::snp_measurement::{
    compute_snp_launch_measurement, SnpMeasurementInputs,
};
use crate::image_builder::enclave::EnclaveImageBuilder as GenericEnclaveImageBuilder;
use crate::image_builder::enclave::EnclaveSettings;
use crate::image_builder::parent::snp::{BLOBS_SUBDIR_GPU_DISABLED, BLOBS_SUBDIR_GPU_ENABLED};
use crate::image_builder::INSTALLATION_DIR;
use crate::{ConverterError, ConverterErrorKind, Result};

pub(crate) struct EnclaveImageBuilder<'a> {
    pub(crate) enclave_image_builder: GenericEnclaveImageBuilder<'a>,
}

impl<'a> EnclaveImageBuilder<'a> {
    const INIT_BIN: &'static str = "init";
    const GPU_MODULES: &'static [&'static str] = &[
        "nvidia.ko",
        "nvidia-uvm.ko",
        "nvidia-drm.ko",
        "nvidia-modeset.ko",
    ];
    pub const INITRAMFS_FILENAME: &'static str = "initramfs.gz";

    pub(crate) async fn create_image(
        &self,
        input_repository: &crate::docker::DockerDaemon,
        enclave_settings: EnclaveSettings,
        user_config: UserConfig,
        env_vars: Vec<String>,
        _sender: std::sync::mpsc::Sender<crate::image::ImageToClean>,
    ) -> Result<SNPEnclavesMeasurements> {
        let work_dir = self.enclave_image_builder.dir.path();

        let start = Instant::now();
        info!("Creating client FS block file...");
        let file_system_config = self
            .enclave_image_builder
            .create_block_file(input_repository, &user_config)
            .await?;
        info!(
            "Client FS block file has been created in {:?}.",
            start.elapsed()
        );

        let start = Instant::now();
        let is_debug = enclave_settings.is_debug;
        let enable_overlay_filesystem_persistence =
            enclave_settings.enable_overlay_filesystem_persistence;
        let ccm_backend_url = enclave_settings.ccm_backend_url.clone();
        let dsm_configuration = enclave_settings.dsm_configuration.clone();

        let enclave_manifest = EnclaveManifest {
            user_config,
            file_system_config,
            is_debug,
            env_vars,
            enable_overlay_filesystem_persistence,
            ccm_backend_url,
            dsm_configuration,
        };

        let enclave_manifest_data =
            serde_json::to_vec(&enclave_manifest).map_err(|err| ConverterError {
                message: format!("Failed serializing enclave settings file. {:?}", err),
                kind: ConverterErrorKind::RequisitesCreation,
            })?;
        info!("Serialized enclave manifest in {:?}.", start.elapsed());

        let enclave_base_tar_path = work_dir.join("enclave-base.tar");
        let start = Instant::now();
        info!("Exporting enclave-base image...");
        let enclave_base_archive = self
            .enclave_image_builder
            .export_enclave_base_file_system(input_repository, &enclave_base_tar_path)
            .await?;
        info!("Exported enclave-base image in {:?}.", start.elapsed());

        let initramfs_file_path = work_dir.join(Self::INITRAMFS_FILENAME);

        let start = Instant::now();
        info!("Creating initramfs archive...");
        create_initramfs(
            &initramfs_file_path,
            enclave_base_archive,
            &enclave_settings,
            &enclave_manifest_data,
        )
        .map_err(|e| ConverterError {
            message: format!("Failed to create initramfs: {}", e),
            kind: ConverterErrorKind::EnclaveImageCreation,
        })?;
        info!("Created initramfs archive in {:?}.", start.elapsed());

        compute_launch_measurements(&enclave_settings, &initramfs_file_path).await
    }

    pub(crate) fn get_enclave_base_image_name(
        enclaves_options: &SNPEnclavesConversionRequestOptions,
    ) -> String {
        env::var("ENCLAVE_IMAGE").unwrap_or_else(|_| {
            if enclaves_options.enable_gpu_passthrough.unwrap_or_default() {
                crate::ENCLAVE_IMAGE_SNP_GPU.to_owned()
            } else {
                crate::ENCLAVE_IMAGE.to_owned()
            }
        })
    }
}

fn create_initramfs(
    output_path: &Path,
    mut enclave_base_archive: Archive<fs::File>,
    enclave_settings: &EnclaveSettings,
    enclave_manifest_data: &[u8],
) -> std::result::Result<(), IoError> {
    let run_cmd = get_run_cmd(&enclave_settings);

    let mut blobs_dir = PathBuf::from(format!("{}/blobs", INSTALLATION_DIR));
    let init = {
        let subdir = if enclave_settings.gpu_passthrough {
            BLOBS_SUBDIR_GPU_ENABLED
        } else {
            BLOBS_SUBDIR_GPU_DISABLED
        };
        blobs_dir.push(subdir);
        blobs_dir.push(EnclaveImageBuilder::INIT_BIN);
        let init_data = fs::read(&blobs_dir)?;
        blobs_dir.pop(); // init_bin
        blobs_dir.pop(); // gpu enabled/disabled subdir
        init_data
    };

    let mut fs_tree = FsTree::new()
        .add_file("env", Cursor::new(get_env_vars(&enclave_settings.env_vars)))
        .add_file("cmd", Cursor::new(run_cmd))
        .add_executable("init", Cursor::new(init));

    // Add enclave-base filesystem to rootfs
    info!("Adding enclave-base filesystem to initramfs rootfs...");
    fs_tree = add_enclave_base_to_initramfs(fs_tree, &mut enclave_base_archive)?;

    // Set up minimal runtime directories. Do not create directories that exist
    // in the target rootfs (e.g., /bin). Since we use mount --move to transition
    // to the new root, pre-existing directories in the initramfs can interfere
    // with the visibility of the rootfs contents or break symbolic links.
    fs_tree = fs_tree
        .add_directory("rootfs/dev")
        .add_directory("rootfs/proc")
        .add_directory("rootfs/run")
        .add_directory("rootfs/sys")
        .add_directory("rootfs/tmp");

    // Add dependencies available as resource
    for resource in GenericEnclaveImageBuilder::IMAGE_BUILD_DEPENDENCIES {
        let path = format!("rootfs{}/{}", INSTALLATION_DIR, resource.name);
        let data = Cursor::new(resource.data);
        fs_tree = if resource.is_executable {
            fs_tree.add_executable(&path, data)
        } else {
            fs_tree.add_file(&path, data)
        };
    }

    // Add enclave-settings.json generated at runtime.
    fs_tree = fs_tree.add_file(
        &format!(
            "rootfs{}/{}",
            INSTALLATION_DIR,
            GenericEnclaveImageBuilder::DEFAULT_ENCLAVE_SETTINGS_FILE
        ),
        Cursor::new(enclave_manifest_data.to_vec()),
    );

    // Add GPU modules if enabled
    if enclave_settings.gpu_passthrough {
        info!("Adding gpu modules to initramfs...");
        blobs_dir.push(BLOBS_SUBDIR_GPU_ENABLED);
        for module in EnclaveImageBuilder::GPU_MODULES {
            blobs_dir.push(module);
            let module_data = fs::read(&blobs_dir)?;
            blobs_dir.pop();
            let path = format!("lib/modules/{}", module);
            fs_tree = fs_tree.add_file(&path, Cursor::new(module_data));
        }
        blobs_dir.pop();
    }

    let start = Instant::now();
    let start = Instant::now();
    let mut last_percent = 0usize;

    info!("Building initramfs, it may take a while depending on size of it...");
    let output_file = fs::File::create(output_path)?;
    Initramfs::from_fs_tree_with_progress(fs_tree, output_file, |current, total| {
        if total == 0 {
            return;
        }

        let percent = current * 100 / total;

        if current == 1 || percent >= last_percent + 10 {
            info!(
                "Building initramfs: {}% ({}/{}) entries, elapsed={:?}",
                percent,
                current,
                total,
                start.elapsed()
            );
            last_percent = percent;
        }
    })
    .map_err(|e| {
        IoError::new(
            IoErrorKind::Other,
            format!("Failed to build initramfs: {:?}", e),
        )
    })?;

    info!(
        "Built initramfs.gz at {} in {:?}",
        output_path.display(),
        start.elapsed()
    );
    Ok(())
}

async fn compute_launch_measurements(
    enclave_settings: &EnclaveSettings,
    initramfs_file_path: &Path,
) -> Result<SNPEnclavesMeasurements> {
    let blobs_dir = Path::new(INSTALLATION_DIR).join("blobs");
    let ovmf_path = blobs_dir.join("OVMF.amdsev.fd");
    let kernel_path = blobs_dir
        .join(if enclave_settings.gpu_passthrough {
            BLOBS_SUBDIR_GPU_ENABLED
        } else {
            BLOBS_SUBDIR_GPU_DISABLED
        })
        .join("bzImage");

    compute_snp_launch_measurement(&SnpMeasurementInputs {
        ovmf: &ovmf_path,
        kernel: &kernel_path,
        initrd: Some(initramfs_file_path),
        cmdline: None,
        vcpus: 2,
    })
    .await
}

fn add_enclave_base_to_initramfs(
    mut fs_tree: FsTree,
    enclave_base_archive: &mut tar::Archive<fs::File>,
) -> std::result::Result<FsTree, IoError> {
    let start = Instant::now();
    let mut entries_count = 0u64;
    let mut files_count = 0u64;
    let mut directories_count = 0u64;
    let mut links_count = 0u64;
    let mut bytes_read = 0u64;
    let mut last_logged_bytes = 0u64;

    let entries = enclave_base_archive.entries()?;
    for entry in entries {
        let mut entry = entry?;
        entries_count += 1;

        let path = entry.path()?.to_path_buf();
        let path_str = path.to_str().ok_or(IoError::new(
            IoErrorKind::Other,
            format!("Invalid path in archive: {:?}", path),
        ))?;

        let target_path = format!("rootfs/{}", path_str);

        let header = entry.header();
        // Some tar archives doesn't preserve modes.
        let mut mode = header.mode().unwrap_or(0o644);

        // Tar entries do not contains file type bits of mode, instead
        // only contains permissions part. Here, we re-set the file type
        // related bits.
        let file_type = match header.entry_type() {
            EntryType::Regular | EntryType::Continuous => SFlag::S_IFREG,
            EntryType::Directory => SFlag::S_IFDIR,
            EntryType::Symlink => SFlag::S_IFLNK,
            EntryType::Link => {
                warn!(
                    "Hard link detected: {}, hard links are treated it as sym links...",
                    path_str
                );
                SFlag::S_IFLNK
            }
            rest => {
                warn!("Unsupported tar entry type: {:?}, file: {}", rest, path_str);
                return Err(IoError::new(
                    IoErrorKind::Other,
                    format!("Unsupported tar entry: {}", path_str),
                ));
            }
        };
        mode |= file_type.bits() as u32;

        let entry_type = header.entry_type();
        fs_tree = if entry_type.is_dir() {
            directories_count += 1;
            fs_tree.add_directory_with_permissions(&target_path, mode)
        } else if entry_type.is_symlink() || entry_type.is_hard_link() {
            // TODO: For now we're treating a hardlink as an softlink.
            // Hard link support is to be added to the fortanix-vme-initramfs.
            links_count += 1;
            let link_target = entry
                .link_name()?
                .ok_or(IoError::new(IoErrorKind::Other, "Missing link target"))?;
            let link_target_str = link_target
                .to_str()
                .ok_or(IoError::new(IoErrorKind::Other, "Invalid symlink target"))?;
            fs_tree.add_symlink_with_permissions(&target_path, link_target_str, mode)
        } else {
            files_count += 1;
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            bytes_read += data.len() as u64;
            fs_tree.add_file_with_permissions(&target_path, Cursor::new(data), mode)
        };

        if entries_count % 1000 == 0
            || bytes_read.saturating_sub(last_logged_bytes) >= 256 * 1024 * 1024
        {
            info!(
                "Adding enclave-base to initramfs: entries={}, files={}, directories={}, links={}, bytes_read={} MiB, elapsed={:?}, latest={}",
                entries_count,
                files_count,
                directories_count,
                links_count,
                bytes_read / 1024 / 1024,
                start.elapsed(),
                target_path
            );
            last_logged_bytes = bytes_read;
        }
    }

    info!(
        "Added enclave-base to initramfs: entries={}, files={}, directories={}, links={}, bytes_read={} MiB, elapsed={:?}",
        entries_count,
        files_count,
        directories_count,
        links_count,
        bytes_read / 1024 / 1024,
        start.elapsed()
    );

    Ok(fs_tree)
}

// Extends the env variables set in conversion request with
// the ones expected by `init` binary.
fn get_env_vars(enclave_env_vars: &Vec<String>) -> String {
    let mut env_vars = enclave_env_vars.clone();
    // Add PATH env variables.
    env_vars.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned());
    env_vars.join("\n")
}

// Formats the command based on the expectation of `init` binary.
fn get_run_cmd(enclave_settings: &EnclaveSettings) -> String {
    let run_cmd = GenericEnclaveImageBuilder::enclave_command_string(
        enclave_settings,
        &Path::new(INSTALLATION_DIR),
        "enclave",
    );

    format!("/bin/sh\n-c\n{}", run_cmd)
}
