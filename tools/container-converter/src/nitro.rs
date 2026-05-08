/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::HashMap;

use crate::hex_response;
use crate::image_builder::nitro::enclave::NitroEnclaveMeasurements;
use crate::{image::ImageWithDetails, Result};
use api_model::{
    converter::{ConvertedImageInfo, HashAlgorithm},
    nitro::{
        NitroEnclavesConfig, NitroEnclavesConversionResponse, NitroEnclavesMeasurements,
        NitroEnclavesVersion,
    },
};

pub const PLATFORM_ABOUT: &str =
    "Converts user docker container to be able to run in AWS Nitro environment";

pub(crate) fn create_response(
    image: &ImageWithDetails,
    measurements: NitroEnclaveMeasurements,
) -> Result<NitroEnclavesConversionResponse> {
    let mut measurements_map = HashMap::new();

    measurements_map.insert(
        NitroEnclavesVersion::NitroEnclaves,
        NitroEnclavesMeasurements {
            hash_algorithm: HashAlgorithm::Sha384,
            pcr0: hex_response(&measurements.pcr_list.pcr0)?,
            pcr1: hex_response(&measurements.pcr_list.pcr1)?,
            pcr2: hex_response(&measurements.pcr_list.pcr2)?,
        },
    );

    let result = NitroEnclavesConversionResponse {
        converted_image: ConvertedImageInfo {
            name: image.reference.to_string(),
            sha: hex_response(image.short_id())?,
            size: image.details.size as usize,
        },

        config: NitroEnclavesConfig {
            measurements: measurements_map,
            pcr8: hex_response(&measurements.pcr_list.pcr8.unwrap_or_default())?,
        },
    };

    Ok(result)
}
