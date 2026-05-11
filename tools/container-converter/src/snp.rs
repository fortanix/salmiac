/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use api_model::{
    converter::ConvertedImageInfo,
    snp::{
        SNPEnclavesConfig, SNPEnclavesConversionResponse,
        SNPEnclavesMeasurements,
    },
};

use crate::{
    hex_response,
    image::ImageWithDetails,
    Result,
};

pub const NAME: &str = "AMD SNP";

pub(crate) fn create_response(
    image: &ImageWithDetails,
    measurements: SNPEnclavesMeasurements,
) -> Result<SNPEnclavesConversionResponse> {
    let result = SNPEnclavesConversionResponse {
        converted_image: ConvertedImageInfo {
            name: image.reference.to_string(),
            sha: hex_response(image.short_id())?,
            size: image.details.size as usize,
        },

        config: SNPEnclavesConfig {
            measurements: SNPEnclavesMeasurements {
                launch_measurement: measurements.launch_measurement,
            },
        },
    };
    Ok(result)
}
