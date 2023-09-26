#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{HexString, ByteUnit};

use std::collections::HashMap;
use std::path::Path;

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NitroEnclavesConversionRequest {
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub request: ConversionRequest,
    pub nitro_enclaves_options: NitroEnclavesConversionRequestOptions,
}

impl NitroEnclavesConversionRequest {
    pub fn is_debug(&self) -> bool {
        self.request.converter_options.debug.unwrap_or(false)
    }
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConversionRequest {
    /// Input docker image name and credentials
    pub input_image: ConversionRequestImageInfo,

    /// Output docker image name and credentials
    pub output_image: ConversionRequestImageInfo,

    /// Different converter request options
    pub converter_options: ConverterOptions,
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConversionRequestImageInfo {
    /// Docker image name
    pub name: String,

    /// Docker credentials
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub auth_config: Option<AuthConfig>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CaCertificateConfig {
    /// Path to expose the CA cert in the application filesystem
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ca_path: Option<String>,

    /// Base64-encoded CA certificate contents.
    /// Not required when converting applications via Enclave Manager.
    /// Required when calling the converter directly,
    /// or if you wish to override the Enclave Manager CA certificate.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub ca_cert: Option<String>,

    /// Request to install CA cert in the system trust store
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub system: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CertificateConfig {
    /// Certificate issuance strategy
    pub issuer: CertIssuer,

    /// Certificate subject common name, typically a DNS name
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub subject: Option<String>,

    /// Subject alternate names to include in the certificate (e.g. DNS:example.com)
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub alt_names: Vec<String>,

    /// Type of key to generate
    pub key_type: KeyType,

    /// Key parameters. Currently must be an instance of RsaKeyParam, but other types may be supported in the future.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub key_param: Option<serde_json::Value>,

    /// Path to expose the key in the application filesystem
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub key_path: Option<String>,

    /// Path to expose the certificate in the application filesystem
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub cert_path: Option<String>,

    /// Path to expose the complete certificate chain in the application filesystem
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub chain_path: Option<String>,
}

impl CertificateConfig {
    pub fn key_path_or_default(&self) -> &Path {
        Path::new(self.key_path.as_ref().map_or("key", |e| e.as_str()))
    }

    pub fn cert_path_or_default(&self) -> &Path {
        Path::new(self.cert_path.as_ref().map_or("cert", |e| e.as_str()))
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CertIssuer {
    ManagerCa,
    Node,
    SelfIas,
}

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum KeyType {
    Rsa,
    // Not yet supported:
    // Ec
}

#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConverterOptions {
    /// Allow command line arguments to EnclaveOS application
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub allow_cmdline_args: Option<bool>,

    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub allow_docker_pull_failure: Option<bool>,

    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub app: Option<serde_json::Value>,

    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub ca_certificates: Vec<CaCertificateConfig>,

    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub certificates: Vec<CertificateConfig>,

    /// Enables debug logging from EnclaveOS
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub debug: Option<bool>,

    /// Override the entrypoint of the original container
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub entry_point: Vec<String>,

    /// Override additional arguments to the container entrypoint
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub entry_point_args: Vec<String>,

    #[cfg_attr(feature = "serde", serde(default = "default_to_true"))]
    pub push_converted_image: Option<bool>,

    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub env_vars: Vec<String>,

    /// Type of the Java JVM used
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub java_mode: Option<String>,

    /// Enable the usage of DSM for the overlay
    /// filesystem persistance
    #[cfg_attr(feature = "serde", serde(default = "default_to_false"))]
    pub enable_overlay_filesystem_persistence: Option<bool>,
}

#[cfg(feature = "serde")]
fn default_to_true() -> Option<bool> {
    Some(true)
}
#[cfg(feature = "serde")]
fn default_to_false() -> Option<bool> {
    Some(false)
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

/// Credentials for authenticating to a docker registry
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuthConfig {
    /// User name for docker registry authentication
    pub username: String,

    /// Password for docker registry authentication
    pub password: String,
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
pub struct ConvertedImageInfo {
    pub name: String,
    pub sha: HexString,
    pub size: usize,
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

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum HashAlgorithm {
    Sha384,
    // more to come here
}

impl CertificateConfig {
    pub fn new() -> CertificateConfig {
        CertificateConfig {
            issuer: CertIssuer::ManagerCa,
            subject: None,
            alt_names: Vec::new(),
            key_type: KeyType::Rsa,
            key_param: None,
            key_path: None,
            cert_path: None,
            chain_path: None,
        }
    }
}
