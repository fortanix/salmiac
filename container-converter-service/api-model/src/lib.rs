use std::collections::HashMap;

use client_generator_base::output_types;
use model_macros::SerdeExtended;
use serde::{Serialize, Deserialize};
use serde_json;
use webservice_api_model::define_apis;

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

define_apis! {
//  Method    Path                     => Operation name  (Input type)                            -> Output type
    post      "/v2/convert-image"      => ConvertImage    (NitroEnclavesConversionRequest)        -> NitroEnclavesConversionResponse
}

#[macro_export]
macro_rules! api_model_nitro_enclaves_converter_types {($m:path) => {$m!{

    #[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
    pub struct NitroEnclavesConversionRequest {
        #[serde(flatten)]
        pub request: ConversionRequest,
        pub nitro_enclaves_options: NitroEnclavesConversionRequestOptions,
    }

    #[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
    pub struct ConversionRequest {
        /// Input docker image name and credentials
        pub input_image: ConversionRequestImageInfo,

        /// Output docker image name and credentials
        pub output_image: ConversionRequestImageInfo,

        /// Different converter request options
        pub converter_options: ConverterOptions,
    }

    #[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
    pub struct ConversionRequestImageInfo {
        /// Docker image name
        pub name: String,

        /// Docker credentials
        #[serde(skip_serializing_if="Option::is_none")]
        pub auth_config: Option<AuthConfig>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct CaCertificateConfig {
        /// Path to expose the CA cert in the application filesystem
        #[serde(skip_serializing_if="Option::is_none")]
        pub ca_path: Option<String>,

        /// Base64-encoded CA certificate contents.
        /// Not required when converting applications via Enclave Manager.
        /// Required when calling the converter directly,
        /// or if you wish to override the Enclave Manager CA certificate.
        #[serde(skip_serializing_if="Option::is_none")]
        pub ca_cert: Option<String>,

        /// Request to install CA cert in the system trust store
        #[serde(skip_serializing_if="Option::is_none")]
        pub system: Option<String>,

    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct CertificateConfig {
        /// Certificate issuance strategy
        pub issuer: CertIssuer,

        /// Certificate subject common name, typically a DNS name
        #[serde(skip_serializing_if="Option::is_none")]
        pub subject: Option<String>,

        /// Subject alternate names to include in the certificate (e.g. DNS:example.com)
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub alt_names: Vec<String>,

        /// Type of key to generate
        pub key_type: KeyType,

        /// Key parameters. Currently must be an instance of RsaKeyParam, but other types may be supported in the future.
        #[serde(skip_serializing_if="Option::is_none")]
        pub key_param: Option<serde_json::Value>,

        /// Path to expose the key in the application filesystem
        #[serde(skip_serializing_if="Option::is_none")]
        pub key_path: Option<String>,

        /// Path to expose the certificate in the application filesystem
        #[serde(skip_serializing_if="Option::is_none")]
        pub cert_path: Option<String>,

        /// Path to expose the complete certificate chain in the application filesystem
        #[serde(skip_serializing_if="Option::is_none")]
        pub chain_path: Option<String>,

    }

    #[derive(Clone, Eq, PartialEq, Debug, Hash)]
    #[serde(rename_all = "CaseInsensitive")]
    pub enum CertIssuer {
        ManagerCa,
        Node,
        SelfIas,
    }

    #[derive(Clone, Eq, PartialEq, Debug, Hash)]
    #[serde(rename_all = "CaseInsensitive")]
    pub enum KeyType {
          Rsa,
          // Not yet supported:
          // Ec
    }

    #[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
    pub struct ConverterOptions {
        /// Allow command line arguments to EnclaveOS application
        #[serde(skip_serializing_if="Option::is_none")]
        pub allow_cmdline_args: Option<bool>,

        #[serde(skip_serializing_if="Option::is_none")]
        pub allow_docker_pull_failure: Option<bool>,

        #[serde(skip_serializing_if="Option::is_none")]
        pub app: Option<serde_json::Value>,

        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub ca_certificates: Vec<CaCertificateConfig>,

        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub certificates: Vec<CertificateConfig>,

        /// Enables debug logging from EnclaveOS
        #[serde(skip_serializing_if="Option::is_none")]
        pub debug: Option<bool>,

        /// Override the entrypoint of the original container
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub entry_point: Vec<String>,

        /// Override additional arguments to the container entrypoint
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub entry_point_args: Vec<String>,

        #[serde(skip_serializing_if="Option::is_none")]
        pub push_converted_image: Option<bool>,

        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub env_vars: Vec<String>,

        /// Type of the Java JVM used
        #[serde(skip_serializing_if="Option::is_none")]
        pub java_mode: Option<String>,
    }

    #[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
    pub struct NitroEnclavesConversionRequestOptions {
        #[serde(skip_serializing_if="Option::is_none")]
        pub cpu_count: Option<u8>,

        /// Override the enclave size, e.g. 2048M. Suffixes K, M, and G are supported.
        #[serde(skip_serializing_if="Option::is_none")]
        pub mem_size: Option<String>,

        // there may be more coming, we don't know at this point of time
    }

    /// Credentials for authenticating to a docker registry
    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    pub struct AuthConfig {
        /// User name for docker registry authentication
        pub username: String,

        /// Password for docker registry authentication
        pub password: String,
    }

    #[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
    pub struct NitroEnclavesConversionResponse {
        /// Converted image details
        #[serde(flatten)]
        pub converted_image: ConvertedImageInfo,

        /// NitroEnclaves configuration of the converted image
        pub config: NitroEnclavesConfig,
    }

    #[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
    pub struct ConvertedImageInfo {
        pub name: String,
        pub sha: String,
        pub size: usize,
    }

    #[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
    pub struct NitroEnclavesConfig {
        // here the key should be different nitro enclaves versions
        /// NitroEnclaves measurements of the converted image
        pub measurements: HashMap<NitroEnclavesVersions, NitroEnclavesMeasurements>,

        /// Signer of the nitro enclaves
        pub pcr8: String,
    }

    #[derive(Clone, Eq, PartialEq, Debug, Hash)]
    #[serde(rename_all = "CaseInsensitive")]
    pub enum NitroEnclavesVersions {
        NitroEnclaves
        // more to come here
    }

    #[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
    pub struct NitroEnclavesMeasurements {
        pub hash_algorithm: HashAlgorithms,
        pub pcr0: String,
        pub pcr1: String,
        pub pcr2: String,
    }

    #[derive(Clone, Eq, PartialEq, Debug, Hash)]
    #[serde(rename_all = "CaseInsensitive")]
    pub enum HashAlgorithms {
        Sha384,
        // more to come here
    }

}}}

api_model_nitro_enclaves_converter_types!(output_types);

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