/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use api_model::EnclavesOptions;
use docker_image_reference::Reference as DockerReference;

use crate::docker::DockerUtil;
use crate::image::ImageWithDetails;
use crate::image_builder::enclave::snp::EnclaveImageBuilder as SnpEnclaveImageBuilder;
use crate::image_builder::parent::ParentImageBuilder as GenericParentImageBuilder;
use crate::Result;

use super::qemu::QemuParentImageBuilder;

pub(crate) struct ParentImageBuilder<'a> {
    pub(crate) parent_image_builder: crate::image_builder::parent::ParentImageBuilder<'a>,
    pub(crate) start_options: EnclavesOptions,
}

impl<'a> ParentImageBuilder<'a> {
    pub(crate) async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        image_reference: DockerReference<'a>,
    ) -> Result<ImageWithDetails<'a>> {
        QemuParentImageBuilder::create_image(self, docker_util, image_reference).await
    }
}

#[async_trait::async_trait]
impl<'a> QemuParentImageBuilder<'a> for ParentImageBuilder<'a> {
    fn parent_image_builder(&self) -> &GenericParentImageBuilder<'a> {
        &self.parent_image_builder
    }

    fn cpu_count(&self) -> u8 {
        self.start_options.cpu_count
    }

    fn mem_size(&self) -> &Option<api_model::ByteUnit> {
        &self.start_options.mem_size
    }

    fn enable_gpu_passthrough(&self) -> Option<bool> {
        self.start_options.enable_gpu_passthrough
    }

    fn platform_name(&self) -> &'static str {
        "snp"
    }

    fn initramfs_filename(&self) -> &'static str {
        SnpEnclaveImageBuilder::INITRAMFS_FILENAME
    }

    fn ovmf_filename(&self) -> &'static str {
        SnpEnclaveImageBuilder::OVMF_FILENAME
    }
}
