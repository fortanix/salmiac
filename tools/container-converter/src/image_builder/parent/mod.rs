/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[cfg(platform = "nitro")]
pub(crate) mod nitro;
#[cfg(platform = "nitro")]
pub(crate) use crate::image_builder::parent::nitro::ParentImageBuilder as PlatformParentImageBuilder;

#[cfg(platform = "snp")]
pub(crate) mod snp;
#[cfg(platform = "snp")]
pub(crate) use self::snp::ParentImageBuilder as PlatformParentImageBuilder;

#[cfg(platform = "simulator")]
pub(crate) mod simulator;
#[cfg(platform = "simulator")]
pub(crate) use self::simulator::ParentImageBuilder as PlatformParentImageBuilder;

use std::fs;
use std::io::Write;
use std::path::Path;

use tempfile::TempDir;

use crate::file::{Resource, UnixFile};
use crate::image_builder::enclave::EnclaveImageBuilder;
use crate::image_builder::INSTALLATION_DIR;
use crate::{file, ConverterError, ConverterErrorKind, Result};

pub struct ParentImageBuilder<'a> {
    pub(crate) parent_image: String,
    pub(crate) dir: &'a TempDir,
}

impl<'a> ParentImageBuilder<'a> {
    pub(crate) const DEFAULT_CPU_COUNT: u8 = 2;

    pub(crate) const DEFAULT_MEMORY_SIZE: u64 = 2048;

    pub(crate) const STARTUP_SCRIPT_NAME: &'static str = "start-parent.sh";

    pub(crate) const BINARY_NAME: &'static str = "parent";

    pub(crate) const IMAGE_BUILD_DEPENDENCIES: &'static [Resource<'static>] = &[
        file::Resource {
            name: ParentImageBuilder::STARTUP_SCRIPT_NAME,
            data: include_bytes!("../../resources/parent/start-parent.sh"),
            is_executable: true,
        },
        file::Resource {
            name: ParentImageBuilder::BINARY_NAME,
            data: include_bytes!("../../resources/parent/parent"),
            is_executable: true,
        },
    ];

    // Moves the files produced by enclave image builders
    // into the build context.
    pub(crate) fn move_enclave_files_into_build_context(
        &self,
        build_context_dir: &Path,
        enclave_file: &str,
    ) -> Result<()> {
        move_file(
            &self.dir.path().join(enclave_file),
            &build_context_dir.join(enclave_file),
        )?;

        move_file(
            &self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_OUT),
            &build_context_dir.join(EnclaveImageBuilder::BLOCK_FILE_OUT),
        )
    }

    fn append_start_enclave_command(
        &self,
        startup_script_path: &Path,
    ) -> std::result::Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(startup_script_path)
            .map_err(|err| format!("Failed to open parent startup script {:?}", err))?;

        let start_enclave_command = self.start_enclave_command();

        file.write_all(start_enclave_command.as_bytes())
            .map_err(|err| format!("Failed to write to file {:?}", err))?;

        file.set_execute()
            .map_err(|err| format!("Cannot change permissions for a file {:?}", err))?;

        Ok(())
    }

    fn start_enclave_command(&self) -> String {
        let install_path = Path::new(INSTALLATION_DIR);
        let parent_bin = install_path.join("parent");

        format!(
            "\n\
             # Parent startup code \n\
             {} \"$@\" ",
            parent_bin.display()
        )
    }

    pub(crate) fn eos_debug_env_var() -> String {
        format!("ENCLAVEOS_DEBUG={}", {
            if cfg!(debug_assertions) {
                "debug"
            } else {
                ""
            }
        })
    }
}

pub(crate) fn move_file(from: &Path, to: &Path) -> Result<()> {
    fs::rename(from, to).map_err(|message| ConverterError {
        message: format!(
            "Failed moving file {} into build context {}. {:?}",
            from.display(),
            to.display(),
            message
        ),
        kind: ConverterErrorKind::RequisitesCreation,
    })
}
