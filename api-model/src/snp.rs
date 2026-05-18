/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    converter::{ConversionRequest, ConvertedImageInfo},
    ByteUnit, HexString,
};

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SNPEnclavesConversionRequest {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub request: ConversionRequest, // Existing model, Refer to more details section above
    #[cfg_attr(feature = "serde", serde(rename = "snp_enclaves_options"))]
    pub enclaves_options: SNPEnclavesConversionRequestOptions,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum NvidiaDriverCapability {
    Compute,
    Utility,
}

impl NvidiaDriverCapability {
    pub fn as_str(&self) -> &'static str {
        match self {
            NvidiaDriverCapability::Compute => "compute",
            NvidiaDriverCapability::Utility => "utility",
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SNPEnclavesConversionRequestOptions {
    // number of (v)CPUs to be used
    pub cpu_count: u8,
    /// Override the enclave VM size, e.g. 2048M. Suffixes K, M, and G are supported.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub mem_size: Option<ByteUnit>,
    // Option to enable/disable gpu_passthrough
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub enable_gpu_passthrough: Option<bool>,
    /// NVIDIA driver capabilities to copy into the protected blockfile when GPU passthrough is
    /// enabled. If omitted, compute and utility are included.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub nvidia_driver_capabilities: Option<Vec<NvidiaDriverCapability>>,
}

impl SNPEnclavesConversionRequest {
    pub fn is_debug(&self) -> bool {
        self.request.converter_options.debug.unwrap_or(false)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SNPEnclavesConversionResponse {
    /// Converted image details                                                    
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub converted_image: ConvertedImageInfo,

    /// SNPEnclaves configuration of the converted image                         
    pub config: SNPEnclavesConfig,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SNPEnclavesConfig {
    /// SNPEnclaves measurements of the converted image
    pub measurements: SNPEnclavesMeasurements,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SNPEnclavesMeasurements {
    pub launch_measurement: HexString,
}
