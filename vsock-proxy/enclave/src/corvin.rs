use mbedtls::x509::Certificate;
use log::{debug, info};
use em_app::utils::models::RuntimeAppConfig;

use crate::certificate::CertificateResult;
use crate::enclave::create_file;

use std::sync::Arc;
use std::path::Path;
use std::fs;

const APPLICATION_CONFIG_DIR: &str = "/opt/fortanix/enclave-os/app-config/ro";

pub fn setup_application_configuration(certificate_info : CertificateResult, ccm_backend_url : &str) -> Result<(), String> {
    info!("Setting up Corvin configuration");

    let app_config = request_application_configuration(certificate_info, ccm_backend_url)?;

    debug!("Received application configuration {:?}", app_config);

    let data = serde_json::to_string(&app_config)
        .map_err(|err| format!("Failed serializing app config to string. {:?}", err))?;

    fs::create_dir_all(Path::new(APPLICATION_CONFIG_DIR))
        .map_err(|err| format!("Failed to create app config directory. {:?}", err))?;

    create_file(Path::new(&format!("{}/app-config.json", APPLICATION_CONFIG_DIR)), &data)
}

fn request_application_configuration(mut certificate_info : CertificateResult, ccm_backend_url : &str) -> Result<RuntimeAppConfig, String> {
    certificate_info.certificate.push('\0');

    let app_cert = Certificate::from_pem_multiple(&certificate_info.certificate.as_bytes())
        .map_err(|e| format!("Parsing certificate failed: {:?}", e))?;

    info!("Requesting application config");

    let (url, port) = {
        let split : Vec<_> = ccm_backend_url.split(":").collect();
        (split[0], split[1].parse::<u16>().unwrap())
    };

    em_app::utils::get_runtime_configuration(
        url,
        port,
        Arc::new(app_cert),
        Arc::new(certificate_info.key),
        None,
        None).map_err(|e| format!("Failed retrieving application configuration: {:?}", e))
}