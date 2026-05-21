/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io::{Cursor, Error as IoError, ErrorKind as IoErrorKind, Read};
use std::path::Path;
use std::{env, fs};

use api_model::enclave::{EnclaveManifest, UserConfig};
use api_model::simulator::SimulatorEnclavesConversionRequestOptions;
use fortanix_vme_initramfs::{FsTree, Initramfs};
use log::{info, warn};
use nix::sys::stat::SFlag;
use tar::{Archive, EntryType};

use crate::image_builder::enclave::EnclaveImageBuilder as GenericEnclaveImageBuilder;
use crate::image_builder::enclave::EnclaveSettings;
use crate::image_builder::INSTALLATION_DIR;
use crate::{ConverterError, ConverterErrorKind, Result};

pub(crate) struct EnclaveImageBuilder<'a> {
    pub(crate) enclave_image_builder: GenericEnclaveImageBuilder<'a>,
}

impl<'a> EnclaveImageBuilder<'a> {
    const INIT_BIN: &'static str = "init";
    pub const INITRAMFS_FILENAME: &'static str = "initramfs.cpio.gz";

    pub(crate) async fn create_image(
        &self,
        input_repository: &crate::docker::DockerDaemon,
        enclave_settings: EnclaveSettings,
        user_config: UserConfig,
        env_vars: Vec<String>,
        _sender: std::sync::mpsc::Sender<crate::image::ImageToClean>,
    ) -> Result<()> {
        let work_dir = self.enclave_image_builder.dir.path();

        let file_system_config = self
            .enclave_image_builder
            .create_block_file(input_repository, &user_config)
            .await?;
        info!("Client FS Block file has been created.");

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

        let enclave_base_tar_path = work_dir.join("enclave-base.tar");
        info!("Exporting enclave-base image...");
        let enclave_base_archive = self
            .enclave_image_builder
            .export_enclave_base_file_system(input_repository, &enclave_base_tar_path)
            .await?;

        let output_file_path = work_dir.join(Self::INITRAMFS_FILENAME);

        info!("Creating initramfs archive...");
        create_initramfs(
            &output_file_path,
            enclave_base_archive,
            &enclave_settings,
            &enclave_manifest_data,
        )
        .map_err(|e| ConverterError {
            message: format!("Failed to create initramfs: {}", e),
            kind: ConverterErrorKind::EnclaveImageCreation,
        })?;

        Ok(())
    }

    pub(crate) fn get_enclave_base_image_name(
        _enclaves_options: &SimulatorEnclavesConversionRequestOptions,
    ) -> String {
        env::var("ENCLAVE_IMAGE").unwrap_or_else(|_| crate::ENCLAVE_IMAGE.to_owned())
    }
}

fn create_initramfs(
    output_path: &Path,
    mut enclave_base_archive: Archive<fs::File>,
    enclave_settings: &EnclaveSettings,
    enclave_manifest_data: &[u8],
) -> std::result::Result<(), IoError> {
    let run_cmd = GenericEnclaveImageBuilder::enclave_command_string(
        enclave_settings,
        &Path::new(INSTALLATION_DIR),
        "enclave",
    );

    let init_path = Path::new(INSTALLATION_DIR)
        .join("blobs")
        .join(EnclaveImageBuilder::INIT_BIN);
    let init = fs::read(init_path)?;

    let mut fs_tree = FsTree::new()
        .add_file("env", Cursor::new(enclave_settings.env_vars.join("\n")))
        .add_file(
            "cmd",
            Cursor::new(format!(
                    "{}\n",
                    run_cmd.split_whitespace().collect::<Vec<_>>().join("\n")
            )),
        )
        .add_executable("init", Cursor::new(init));

    // Add enclave-base filesystem to rootfs
    info!("Adding enclave-base filesystem to initramfs rootfs...");
    fs_tree = add_enclave_base_to_initramfs(fs_tree, &mut enclave_base_archive)?;

    // Ensure basic rootfs structure exists for `init`, even if missing from enclave-base.
    fs_tree = fs_tree
        .add_directory("rootfs/dev")
        .add_directory("rootfs/proc")
        .add_directory("rootfs/run")
        .add_directory("rootfs/sys")
        .add_directory("rootfs/tmp")
        .add_directory("rootfs/bin");

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

    info!("Building initramfs, it may take a while depending on size of it...");
    let output_file = fs::File::create(output_path)?;
    Initramfs::from_fs_tree(fs_tree, output_file).map_err(|e| {
        IoError::new(
            IoErrorKind::Other,
            format!("Failed to build initramfs: {:?}", e),
        )
    })?;

    info!("Built initramfs.cpio.gz at {}", output_path.display());
    Ok(())
}

fn add_enclave_base_to_initramfs(
    mut fs_tree: FsTree,
    enclave_base_archive: &mut tar::Archive<fs::File>,
) -> std::result::Result<FsTree, IoError> {
    let entries = enclave_base_archive.entries()?;
    for entry in entries {
        let mut entry = entry?;
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
            fs_tree.add_directory_with_permissions(&target_path, mode)
        } else if entry_type.is_symlink() || entry_type.is_hard_link() {
            // TODO: For now we're treating a hardlink as an softlink.
            // Hard link support is to be added to the fortanix-vme-initramfs.
            let link_target = entry
                .link_name()?
                .ok_or(IoError::new(IoErrorKind::Other, "Missing link target"))?;
            let link_target_str = link_target
                .to_str()
                .ok_or(IoError::new(IoErrorKind::Other, "Invalid symlink target"))?;
            fs_tree.add_symlink_with_permissions(&target_path, link_target_str, mode)
        } else {
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            fs_tree.add_file_with_permissions(&target_path, Cursor::new(data), mode)
        }
    }

    Ok(fs_tree)
}
