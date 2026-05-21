/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    converter::{ConversionRequest, ConvertedImageInfo},
    ByteUnit,
};

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SimulatorEnclavesConversionRequest {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub request: ConversionRequest,

    pub enclaves_options: SimulatorEnclavesConversionRequestOptions,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SimulatorEnclavesConversionRequestOptions {
    pub cpu_count: u8,

    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub mem_size: Option<ByteUnit>,
}

impl SimulatorEnclavesConversionRequest {
    pub fn is_debug(&self) -> bool {
        self.request.converter_options.debug.unwrap_or(false)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SimulatorEnclavesConversionResponse {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub converted_image: ConvertedImageInfo,

    pub config: SimulatorEnclavesConfig,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SimulatorEnclavesConfig {}
