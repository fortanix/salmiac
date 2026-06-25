use crate::HexString;
use crate::{
    converter::{ConversionRequest, ConvertedImageInfo},
    ByteUnit, NvidiaDriverCapability,
};

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TDXEnclaveConversionRequest {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub request: ConversionRequest, // Existing model, Refer to more details section above
    #[cfg_attr(feature = "serde", serde(rename = "tdx_enclave_options"))]
    pub enclaves_options: TDXEnclaveConversionRequestOptions,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TDXEnclaveConversionRequestOptions {
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
pub struct TDXEnclaveConversionResponse {
    /// Converted image details
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub converted_image: ConvertedImageInfo,

    /// TDXEnclave configuration of the converted image
    pub config: TDXEnclaveConfig,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TDXEnclaveConfig {
    /// TDXEnclave measurements of the converted image
    pub measurements: TDXEnclaveMeasurements,
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TDXEnclaveMeasurements {
    pub mrtd: HexString,
    pub rtmr0: HexString,
    pub rtmr1: HexString,
    pub rtmr2: HexString,
    pub rtmr3: HexString,
}
