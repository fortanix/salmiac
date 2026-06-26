/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::PathBuf;
use crate::image_builder::INSTALLATION_DIR;

const BLOBS_SUBDIR_GPU_ENABLED: &'static str = "kernel_enabled_gpu";
const BLOBS_SUBDIR_GPU_DISABLED: &'static str = "kernel_disabled_gpu";

pub(crate) struct BlobFinder;

impl BlobFinder {
    pub(crate) fn blobs_dir() -> PathBuf {
        PathBuf::from(INSTALLATION_DIR).join("blobs")
    }

    pub(crate) fn kernel_blobs_dir(gpu_passthrough: bool) -> PathBuf {
        let subdir = if gpu_passthrough {
            BLOBS_SUBDIR_GPU_ENABLED
        } else {
            BLOBS_SUBDIR_GPU_DISABLED
        };
        Self::blobs_dir().join(subdir)
    }

    pub(crate) fn ovmf_path(ovmf_filename: &str) -> PathBuf {
        Self::blobs_dir().join(ovmf_filename)
    }

    pub(crate) fn kernel_path(gpu_passthrough: bool) -> PathBuf {
        Self::kernel_blobs_dir(gpu_passthrough).join("bzImage")
    }

    pub(crate) fn kernel_config_path(gpu_passthrough: bool) -> PathBuf {
        Self::kernel_blobs_dir(gpu_passthrough).join("bzImage.config")
    }
}
