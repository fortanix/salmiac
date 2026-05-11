/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use api_model::snp::SNPEnclavesConversionRequestOptions;

use crate::{image::ImageWithDetails, Result};

pub(crate) struct ParentImageBuilder<'a> {
    pub(crate) parent_image_builder: crate::image_builder::parent::ParentImageBuilder<'a>,
    pub(crate) start_options: SNPEnclavesConversionRequestOptions,
}
impl<'a> ParentImageBuilder<'a> {
    // TODO: RTE-941
    pub(crate) async fn create_image(
        &self,
        input_repository: &crate::docker::DockerDaemon,
        output_image: docker_image_reference::Reference<'_>,
    ) -> Result<ImageWithDetails<'a>> {
        todo!()
    }
}
