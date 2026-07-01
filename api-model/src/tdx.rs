/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::HexString;
use crate::{
    converter::{ConversionRequest, ConvertedImageInfo},
    ByteUnit, NvidiaDriverCapability,
};

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TdxEnclavesConversionRequest {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub request: ConversionRequest, // Existing model, Refer to more details section above
    #[cfg_attr(feature = "serde", serde(rename = "tdx_enclaves_options"))]
    pub enclaves_options: TdxEnclavesConversionRequestOptions,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TdxEnclavesConversionRequestOptions {
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

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TdxEnclavesConversionResponse {
    /// Converted image details
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub converted_image: ConvertedImageInfo,

    /// TdxEnclaves configuration of the converted image
    pub config: TdxEnclavesConfig,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TdxEnclavesConfig {
    /// TdxEnclaves measurements of the converted image
    pub measurements: TdxEnclavesMeasurements,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TdxEnclavesMeasurements {
    pub mrtd: HexString,
    pub rtmr0: HexString,
    pub rtmr1: HexString,
    pub rtmr2: HexString,
    pub rtmr3: HexString,
}
