use mbedtls::x509::Certificate;
use mbedtls::alloc::{List as MbedtlsList};
use log::{info};
use em_app::utils::models::RuntimeAppConfig;

use shared::device::{CCMBackendUrl};
use crate::certificate::CertificateResult;
use crate::enclave::write_to_file;

use std::sync::Arc;
use std::path::Path;
use std::fs;

const APPLICATION_CONFIG_DIR: &str = "/opt/fortanix/enclave-os/app-config/rw";

const APPLICATION_CONFIG_FILE: &str = "/opt/fortanix/enclave-os/app-config/rw/app-config.json";

pub fn setup_application_configuration(certificate_info : CertificateResult, ccm_backend_url : &CCMBackendUrl, skip_server_verify: bool) -> Result<(), String> {
    info!("Setting up application configuration.");

    let app_config = request_application_configuration(certificate_info, ccm_backend_url, skip_server_verify)?;

    let data = serde_json::to_string(&app_config)
        .map_err(|err| format!("Failed serializing app config to string. {:?}", err))?;

    fs::create_dir_all(Path::new(APPLICATION_CONFIG_DIR))
        .map_err(|err| format!("Failed to create app config directory. {:?}", err))?;

    write_to_file(Path::new(APPLICATION_CONFIG_FILE), &data)
}

fn request_application_configuration(mut certificate_info : CertificateResult, ccm_backend_url : &CCMBackendUrl, skip_server_verify: bool) -> Result<RuntimeAppConfig, String> {
    certificate_info.certificate.push('\0');

    let app_cert = Certificate::from_pem_multiple(&certificate_info.certificate.as_bytes())
        .map_err(|e| format!("Parsing certificate failed: {:?}", e))?;

    info!("Requesting application configuration.");

    let ca_cert_list = if skip_server_verify {
        None
    } else {
        Some(Arc::new(read_root_certificates()))
    };

    em_app::utils::get_runtime_configuration(
        &ccm_backend_url.host,
        ccm_backend_url.port,
        Arc::new(app_cert),
        Arc::new(certificate_info.key),
        ca_cert_list,
        None).map_err(|e| format!("Failed retrieving application configuration: {:?}", e))
}

fn read_root_certificates() -> MbedtlsList<Certificate> {
    let file_contents = include_bytes!(concat!(env!("OUT_DIR"), "/cert_list"));

    let ca_cert_list: Vec<Vec<u8>> = serde_cbor::from_slice(&file_contents[..])
        .expect("Failed deserializing root certificate list");

    let mut result = MbedtlsList::<Certificate>::new();
    for i in ca_cert_list {
        result.push(Certificate::from_der(&i).expect("Failed parsing ca certificate"));
    }

    result
}