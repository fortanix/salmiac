/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use api_model::{
    converter::ConvertedImageInfo,
    simulator::{SimulatorEnclavesConfig, SimulatorEnclavesConversionResponse},
};

use crate::{hex_response, image::ImageWithDetails, Result};

pub const NAME: &str = "Simulator";

pub(crate) fn create_response(
    image: &ImageWithDetails,
    _: (),
) -> Result<SimulatorEnclavesConversionResponse> {
    Ok(SimulatorEnclavesConversionResponse {
        converted_image: ConvertedImageInfo {
            name: image.reference.to_string(),
            sha: hex_response(image.short_id())?,
            size: image.details.size as usize,
        },
        config: SimulatorEnclavesConfig {},
    })
}
