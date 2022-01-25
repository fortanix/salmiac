use em_app::utils::models::{RuntimeAppConfig, ApplicationConfigExtra};
use log::info;
use mbedtls::alloc::List as MbedtlsList;
use mbedtls::x509::Certificate;
use mbedtls::pk::Pk;

use crate::certificate::CertificateResult;
use crate::enclave::write_to_file;
use shared::device::CCMBackendUrl;

use std::fs;
use std::path::Path;
use std::sync::Arc;

const APPLICATION_CONFIG_DIR: &str = "/opt/fortanix/enclave-os/app-config/rw";

const APPLICATION_CONFIG_FILE: &str = "/opt/fortanix/enclave-os/app-config/rw/app-config.json";

macro_rules! dataset_dir {
    () => {
        "/opt/fortanix/enclave-os/app-config/rw/{}/{}/dataset"
    };
}

macro_rules! application_dir {
    () => {
        "/opt/fortanix/enclave-os/app-config/rw/{}/{}/application"
    };
}

const CREDENTIALS_FILE: &str = "credentials.bin";

const LOCATION_FILE: &str = "location.txt";

pub fn setup_application_configuration(
    certificate_info: CertificateResult,
    ccm_backend_url: &CCMBackendUrl,
    skip_server_verify: bool,
) -> Result<(), String> {
    info!("Setting up application configuration.");

    let em_app_credentials = EmAppCredentials::new(certificate_info, skip_server_verify)?;

    let app_config = setup_runtime_configuration(ccm_backend_url, &em_app_credentials)?;

    setup_datasets(&app_config.extra, &em_app_credentials)
}

fn setup_runtime_configuration(
    ccm_backend_url: &CCMBackendUrl,
    credentials: &EmAppCredentials,
) -> Result<RuntimeAppConfig, String> {
    info!("Requesting application configuration.");

    let app_config = em_app::utils::get_runtime_configuration(
        &ccm_backend_url.host,
        ccm_backend_url.port,
        credentials.certificate.clone(),
        credentials.key.clone(),
        credentials.root_certificate.clone(),
        None,
    )
    .map_err(|e| format!("Failed retrieving application configuration: {:?}", e))?;

    let data =
        serde_json::to_string(&app_config).map_err(|err| format!("Failed serializing app config to string. {:?}", err))?;

    fs::create_dir_all(Path::new(APPLICATION_CONFIG_DIR))
        .map_err(|err| format!("Failed to create app config directory. {:?}", err))?;

    write_to_file(Path::new(APPLICATION_CONFIG_FILE), &data)
        .map_err(|err| format!("Failed to write data to application config file. {:?}", err))?;

    Ok(app_config)
}

fn setup_datasets(config: &ApplicationConfigExtra, credentials: &EmAppCredentials) -> Result<(), String> {
    info!("Requesting application data sets.");

    let connections_map = config
        .connections
        .as_ref()
        .ok_or("Missing connections field in runtime config")?;

    for (port, connections) in connections_map {
        for (name, object) in connections {
            if let Some(dataset) = &object.dataset {
                if let Some(sdkms_credentials) = &dataset.credentials.sdkms {
                    let response = em_app::utils::get_sdkms_dataset(
                        sdkms_credentials.credentials_url.clone(),
                        sdkms_credentials.credentials_key_name.clone(),
                        sdkms_credentials.sdkms_app_id,
                        credentials.certificate.clone(),
                        credentials.key.clone(),
                        credentials.root_certificate.clone(),
                        None,
                    )
                    .map_err(|e| format!("Failed retrieving dataset: {:?}", e))?;

                    let dir = format!(dataset_dir!(), port, name);
                    let dataset_dir = Path::new(&dir);
                    let dataset_file = dataset_dir.join(CREDENTIALS_FILE);
                    let location_file = dataset_dir.join(LOCATION_FILE);

                    fs::create_dir_all(dataset_dir)
                        .map_err(|err| format!("Failed to create data set directory. {:?}", err))?;

                    fs::write(dataset_file.clone(), &response).map_err(|err| {
                        format!(
                            "Failed to write data set into a file {}. {:?}",
                            dataset_file.display(),
                            err
                        )
                    })?;

                    fs::write(location_file.clone(), &dataset.location).map_err(|err| {
                        format!(
                            "Failed to write location into a file {}. {:?}",
                            location_file.display(),
                            err
                        )
                    })?;
                }
            } else if let Some(application) = &object.application {
                let dir = format!(application_dir!(), port, name);
                let application_dir = Path::new(&dir);
                let location_file = application_dir.join(LOCATION_FILE);

                fs::create_dir_all(application_dir)
                    .map_err(|err| format!("Failed to create application directory. {:?}", err))?;

                fs::write(location_file.clone(), &application.workflow_domain).map_err(|err| {
                    format!(
                        "Failed to write workflow domain into a file {}. {:?}",
                        location_file.display(),
                        err
                    )
                })?;
            }
        }
    }

    Ok(())
}

fn read_root_certificates() -> MbedtlsList<Certificate> {
    let file_contents = include_bytes!(concat!(env!("OUT_DIR"), "/cert_list"));

    let ca_cert_list: Vec<Vec<u8>> =
        serde_cbor::from_slice(&file_contents[..]).expect("Failed deserializing root certificate list");

    let mut result = MbedtlsList::<Certificate>::new();
    for i in ca_cert_list {
        result.push(Certificate::from_der(&i).expect("Failed parsing ca certificate"));
    }

    result
}

struct EmAppCredentials {
    certificate: Arc<MbedtlsList<Certificate>>,

    key: Arc<Pk>,

    root_certificate: Option<Arc<MbedtlsList<Certificate>>>,
}

impl EmAppCredentials {
    pub fn new(mut certificate_info: CertificateResult, skip_server_verify: bool) -> Result<Self, String> {
        let certificate = {
            certificate_info.certificate.push('\0');

            let app_cert = Certificate::from_pem_multiple(&certificate_info.certificate.as_bytes())
                .map_err(|e| format!("Parsing certificate failed: {:?}", e))?;

            Arc::new(app_cert)
        };

        let key = Arc::new(certificate_info.key);

        let root_certificate = if skip_server_verify {
            None
        } else {
            Some(Arc::new(read_root_certificates()))
        };

        Ok(EmAppCredentials {
            certificate,
            key,
            root_certificate,
        })
    }
}
