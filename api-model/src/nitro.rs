/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    converter::{ConversionRequest, ConvertedImageInfo, HashAlgorithm},
    ByteUnit, HexString,
};

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NitroEnclavesConversionRequest {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub request: ConversionRequest,
    pub enclaves_options: NitroEnclavesConversionRequestOptions,
}

impl NitroEnclavesConversionRequest {
    pub fn is_debug(&self) -> bool {
        self.request.converter_options.debug.unwrap_or(false)
    }
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NitroEnclavesConversionRequestOptions {
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub cpu_count: Option<u8>,

    /// Override the enclave size, e.g. 2048M. Suffixes K, M, and G are supported.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub mem_size: Option<ByteUnit>,
    // there may be more coming, we don't know at this point of time
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NitroEnclavesConversionResponse {
    /// Converted image details                                
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub converted_image: ConvertedImageInfo,

    /// NitroEnclaves configuration of the converted image     
    pub config: NitroEnclavesConfig,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NitroEnclavesConfig {
    // here the key should be different nitro enclaves versions
    /// NitroEnclaves measurements of the converted image                       
    pub measurements: HashMap<NitroEnclavesVersion, NitroEnclavesMeasurements>,

    /// Signer of the nitro enclaves                                            
    pub pcr8: HexString,
}

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NitroEnclavesVersion {
    NitroEnclaves, // more to come here
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NitroEnclavesMeasurements {
    pub hash_algorithm: HashAlgorithm,
    pub pcr0: HexString,
    pub pcr1: HexString,
    pub pcr2: HexString,
}
