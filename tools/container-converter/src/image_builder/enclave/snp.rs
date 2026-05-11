/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use api_model::snp::SNPEnclavesMeasurements;

use crate::Result;

pub(crate) struct EnclaveImageBuilder<'a> {
    pub(crate) enclave_image_builder: crate::image_builder::enclave::EnclaveImageBuilder<'a>
}
impl<'a> EnclaveImageBuilder<'a> {
    // TODO: RTE-941
    pub(crate) async fn create_image(
        &self,
        input_repository: &crate::docker::DockerDaemon,
        enclave_settings: crate::image_builder::enclave::EnclaveSettings,
        user_config: api_model::enclave::UserConfig,
        image_env_vars: Vec<String>,
        sender: std::sync::mpsc::Sender<crate::image::ImageToClean>,
    ) -> Result<SNPEnclavesMeasurements> {
        todo!()
    }
}
