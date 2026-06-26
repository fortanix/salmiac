/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use log::{info, warn};
use std::fs;
use std::io::{Cursor, Error as IoError, ErrorKind as IoErrorKind, Read};
use std::path::{Path, PathBuf};
use std::result::Result as StdResult;
use std::time::Instant;

use fortanix_vme_initramfs::{FsTree, Initramfs};
use nix::sys::stat::SFlag;
use tar::{Archive, EntryType};

use crate::image_builder::enclave::qemu::DEFAULT_PATH;
use crate::image_builder::enclave::EnclaveSettings;
use crate::image_builder::enclave::GenericEnclaveImageBuilder;
use crate::image_builder::INSTALLATION_DIR;

#[cfg(any(platform = "snp", platform = "tdx"))]
pub(crate) use gpu_supported::GpuSupportedInitramfsBuilder;

const INIT_BIN: &str = "init";

pub(crate) trait InitramfsBuilder {
    fn kernel_blobs_dir(enclave_settings: &EnclaveSettings) -> PathBuf;
    fn add_kernel_modules(
        fs_tree: FsTree,
        blobs_dir: &Path,
        enclave_settings: &EnclaveSettings,
    ) -> StdResult<FsTree, IoError>;

    fn blobs_dir() -> PathBuf {
        PathBuf::from(INSTALLATION_DIR).join("blobs")
    }

    fn read_init(blobs_dir: &Path) -> StdResult<Vec<u8>, IoError> {
        let init_path = blobs_dir.join(INIT_BIN);
        fs::read(&init_path)
    }

    fn add_basic_fs(
        mut fs_tree: FsTree,
        blobs_dir: &Path,
        enclave_settings: &EnclaveSettings,
    ) -> StdResult<FsTree, IoError> {
        let run_cmd = get_run_cmd(&enclave_settings);
        let init = Self::read_init(blobs_dir)?;
        fs_tree = fs_tree
            .add_file("env", Cursor::new(get_env_vars(&enclave_settings.env_vars)))
            .add_file("cmd", Cursor::new(run_cmd))
            .add_executable("init", Cursor::new(init));
        Ok(fs_tree)
    }

    fn add_resources(mut fs_tree: FsTree, enclave_manifest: &[u8]) -> StdResult<FsTree, IoError> {
        let rootfs_installation_dir = PathBuf::from(format!("rootfs{}", INSTALLATION_DIR));

        // Add dependencies available as resource
        for resource in GenericEnclaveImageBuilder::IMAGE_BUILD_DEPENDENCIES {
            let path = rootfs_installation_dir.join(resource.name);
            let data = Cursor::new(resource.data);
            fs_tree = if resource.is_executable {
                fs_tree.add_executable(&path, data)
            } else {
                fs_tree.add_file(&path, data)
            };
        }

        // Add enclave-settings.json generated at runtime.
        fs_tree = fs_tree.add_file(
            rootfs_installation_dir.join(GenericEnclaveImageBuilder::DEFAULT_ENCLAVE_SETTINGS_FILE),
            Cursor::new(enclave_manifest.to_vec()),
        );

        Ok(fs_tree)
    }

    fn build(
        output: &Path,
        enclave_settings: &EnclaveSettings,
        mut enclave_base_archive: Archive<fs::File>,
        enclave_manifest: &[u8],
    ) -> StdResult<(), IoError> {
        let kernel_blobs_dir = Self::kernel_blobs_dir(enclave_settings);

        let mut fs_tree = Self::add_basic_fs(FsTree::new(), &kernel_blobs_dir, enclave_settings)?;
        fs_tree = add_enclave_base_to_initramfs(fs_tree, &mut enclave_base_archive)?;
        fs_tree = Self::add_resources(fs_tree, enclave_manifest)?;
        fs_tree = Self::add_kernel_modules(fs_tree, &kernel_blobs_dir, enclave_settings)?;

        let start = Instant::now();

        info!("Building initramfs, it may take a while depending on size of it...");
        let output_file = fs::File::create(output)?;
        Initramfs::from_fs_tree(fs_tree, output_file).map_err(|e| {
            IoError::new(
                IoErrorKind::Other,
                format!("failed to build initramfs: {:?}", e),
            )
        })?;

        info!(
            "Built initramfs at {} in {:?}",
            output.display(),
            start.elapsed()
        );
        Ok(())
    }
}

#[cfg(any(platform = "snp", platform = "tdx"))]
mod gpu_supported {
    /// Some fields of enclave_settings are platform-specific.
    /// To avoid compilation errors for platforms without these fields,
    /// the types and implementation are put in a separate module
    /// and only enabled for the correct platform.
    use crate::image_builder::enclave::nvidia;

    use super::*;

    const BLOBS_SUBDIR_GPU_ENABLED: &str = "kernel_enabled_gpu";
    const BLOBS_SUBDIR_GPU_DISABLED: &str = "kernel_disabled_gpu";

    pub(crate) struct GpuSupportedInitramfsBuilder;

    impl InitramfsBuilder for GpuSupportedInitramfsBuilder {
        fn kernel_blobs_dir(enclave_settings: &EnclaveSettings) -> PathBuf {
            let blobs_dir = Self::blobs_dir();
            let subdir = if enclave_settings.gpu_passthrough {
                BLOBS_SUBDIR_GPU_ENABLED
            } else {
                BLOBS_SUBDIR_GPU_DISABLED
            };
            blobs_dir.join(subdir)
        }

        // Adds nvidia kernel modules and firmwares
        // if gpu passthrough is enabled.
        fn add_kernel_modules(
            mut fs_tree: FsTree,
            blobs_dir: &Path,
            enclave_settings: &EnclaveSettings,
        ) -> StdResult<FsTree, IoError> {
            if enclave_settings.gpu_passthrough {
                info!("Adding gpu modules to initramfs...");
                let initramfs_module_path = Path::new("lib/modules");

                for module in nvidia::KERNEL_MODULES {
                    let module_path = blobs_dir.join(module);
                    let module_data = fs::read(module_path)?;

                    // Add gpu drivers to initramfs root as they are loaded by init
                    fs_tree = fs_tree
                        .add_file(initramfs_module_path.join(module), Cursor::new(module_data));
                }

                info!("Adding NVIDIA GSP firmware to initramfs...");
                fs_tree = add_nvidia_firmware_to_initramfs(fs_tree)?;
            }

            Ok(fs_tree)
        }
    }

    fn add_nvidia_firmware_to_initramfs(fs_tree: FsTree) -> std::result::Result<FsTree, IoError> {
        let firmware_root = Path::new(nvidia::NVIDIA_DRIVER_FIRMWARE_PAYLOAD_ROOT);
        if !firmware_root.exists() {
            return Err(IoError::new(
                IoErrorKind::NotFound,
                format!(
                    "NVIDIA firmware payload root {} does not exist in the converter image",
                    firmware_root.display()
                ),
            ));
        }

        add_nvidia_firmware_dir_to_initramfs(fs_tree, firmware_root, firmware_root)
    }

    fn add_nvidia_firmware_dir_to_initramfs(
        mut fs_tree: FsTree,
        root: &Path,
        dir: &Path,
    ) -> std::result::Result<FsTree, IoError> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            let relative_path = path.strip_prefix(root).map_err(|err| {
                IoError::new(
                    IoErrorKind::Other,
                    format!(
                        "failed to make NVIDIA firmware path {} relative to {}. {:?}",
                        path.display(),
                        root.display(),
                        err
                    ),
                )
            })?;
            let relative_path = relative_path.to_str().ok_or(IoError::new(
                IoErrorKind::Other,
                format!("invalid NVIDIA firmware path: {}", path.display()),
            ))?;

            if file_type.is_dir() {
                fs_tree = fs_tree.add_directory(relative_path);
                fs_tree = add_nvidia_firmware_dir_to_initramfs(fs_tree, root, &path)?;
            } else if file_type.is_file() {
                let data = fs::read(&path)?;
                fs_tree = fs_tree.add_file(relative_path, Cursor::new(data));
            } else {
                warn!(
                    "Skipping unsupported NVIDIA firmware entry {}",
                    path.display()
                );
            }
        }

        Ok(fs_tree)
    }
}

#[cfg(platform = "simulator")]
pub(crate) struct BasicInitramfsBuilder;

#[cfg(platform = "simulator")]
impl InitramfsBuilder for BasicInitramfsBuilder {
    fn kernel_blobs_dir(_enclave_settings: &EnclaveSettings) -> PathBuf {
        Self::blobs_dir()
    }

    fn add_kernel_modules(
        fs_tree: FsTree,
        _blobs_dir: &Path,
        _enclave_settings: &EnclaveSettings,
    ) -> StdResult<FsTree, IoError> {
        Ok(fs_tree)
    }
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

        let path = entry.path()?;
        let target_path = Path::new("rootfs").join(&path);

        let header = entry.header();
        // Some tar archives doesn't preserve modes.
        let mut mode = header.mode()?;

        // Tar entries do not contains file type bits of mode, instead
        // only contains permissions part. Here, we re-set the file type
        // related bits.
        let file_type = match header.entry_type() {
            EntryType::Regular | EntryType::Continuous => SFlag::S_IFREG,
            EntryType::Directory => SFlag::S_IFDIR,
            EntryType::Symlink => SFlag::S_IFLNK,
            EntryType::Link => {
                warn!(
                    "Hard link detected: {}, hard links are treated as symbolic links...",
                    path.display(),
                );
                SFlag::S_IFLNK
            }
            rest => {
                warn!(
                    "Unsupported tar entry type: {:?}, file: {}",
                    rest,
                    path.display()
                );
                return Err(IoError::new(
                    IoErrorKind::Other,
                    format!("unsupported tar entry: {}", path.display()),
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
                .ok_or(IoError::new(IoErrorKind::Other, "missing link target"))?;
            fs_tree.add_symlink_with_permissions(&target_path, link_target, mode)
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
                target_path.display(),
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

pub(crate) fn get_env_vars(enclave_env_vars: &Vec<String>) -> String {
    let mut env_vars = enclave_env_vars.clone();
    env_vars.push(format!("PATH={DEFAULT_PATH}"));
    env_vars.join("\n")
}

pub(crate) fn get_run_cmd(enclave_settings: &EnclaveSettings) -> String {
    let run_cmd = GenericEnclaveImageBuilder::enclave_command_string(
        enclave_settings,
        &Path::new(INSTALLATION_DIR),
        "enclave",
    );

    format!("/bin/sh\n-c\n{}", run_cmd)
}
