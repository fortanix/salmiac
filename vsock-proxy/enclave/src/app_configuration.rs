use em_app::utils::models::{ApplicationConfigExtra, RuntimeAppConfig};
use em_client::models::ApplicationConfigSdkmsCredentials;
use log::info;
use mbedtls::alloc::List as MbedtlsList;
use mbedtls::pk::Pk;
use mbedtls::x509::Certificate;
use sdkms::api_model::Blob;

use crate::certificate::CertificateResult;
use crate::enclave::write_to_file;
use shared::device::CCMBackendUrl;

use std::fs;
use std::path::{Path, PathBuf};
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
    api: Box<dyn ApplicationConfiguration>,
) -> Result<(), String> {
    info!("Setting up application configuration.");

    let em_app_credentials = EmAppCredentials::new(certificate_info, skip_server_verify)?;

    let app_config = setup_runtime_configuration(ccm_backend_url, &em_app_credentials, &api.runtime_config_api())?;

    setup_datasets(&app_config.extra, &em_app_credentials, &api.dataset_api())
}

fn setup_runtime_configuration(
    ccm_backend_url: &CCMBackendUrl,
    credentials: &EmAppCredentials,
    api: &Box<dyn RuntimeConfiguration>,
) -> Result<RuntimeAppConfig, String> {
    info!("Requesting application configuration.");

    let app_config = api.get_runtime_configuration(&ccm_backend_url, &credentials)?;

    let data =
        serde_json::to_string(&app_config).map_err(|err| format!("Failed serializing app config to string. {:?}", err))?;

    fs::create_dir_all(Path::new(APPLICATION_CONFIG_DIR))
        .map_err(|err| format!("Failed to create app config directory. {:?}", err))?;

    write_to_file(Path::new(APPLICATION_CONFIG_FILE), &data)
        .map_err(|err| format!("Failed to write data to application config file. {:?}", err))?;

    Ok(app_config)
}

fn setup_datasets(
    config: &ApplicationConfigExtra,
    credentials: &EmAppCredentials,
    api: &Box<dyn SdkmsDataset>,
) -> Result<(), String> {
    info!("Requesting application data sets.");

    let connections_map = config
        .connections
        .as_ref()
        .ok_or("Missing connections field in runtime config")?;

    for (port, connections) in connections_map {
        for (name, object) in connections {
            if let Some(dataset) = &object.dataset {
                if let Some(sdkms_credentials) = &dataset.credentials.sdkms {
                    let response = api.get_dataset(sdkms_credentials, credentials)?;

                    let files = DataSetFiles::new(name, port);

                    fs::create_dir_all(&files.dataset_dir)
                        .map_err(|err| format!("Failed to create data set directory. {:?}", err))?;

                    fs::write(&files.credentials_file, &response).map_err(|err| {
                        format!(
                            "Failed to write data set into a file {}. {:?}",
                            files.credentials_file.display(),
                            err
                        )
                    })?;

                    fs::write(&files.location_file, &dataset.location).map_err(|err| {
                        format!(
                            "Failed to write location into a file {}. {:?}",
                            files.location_file.display(),
                            err
                        )
                    })?;
                }
            } else if let Some(application) = &object.application {
                let files = ApplicationFiles::new(name, port);

                fs::create_dir_all(&files.application_dir)
                    .map_err(|err| format!("Failed to create application directory. {:?}", err))?;

                fs::write(&files.location_file, &application.workflow_domain).map_err(|err| {
                    format!(
                        "Failed to write workflow domain into a file {}. {:?}",
                        files.location_file.display(),
                        err
                    )
                })?;
            }
        }
    }

    Ok(())
}

struct DataSetFiles {
    pub dataset_dir: PathBuf,

    pub credentials_file: PathBuf,

    pub location_file: PathBuf,
}

impl DataSetFiles {
    pub fn new(name: &str, port: &str) -> Self {
        let dir = format!(dataset_dir!(), port, name);
        let dataset_dir = Path::new(&dir).to_path_buf();
        let credentials_file = dataset_dir.join(CREDENTIALS_FILE);
        let location_file = dataset_dir.join(LOCATION_FILE);

        DataSetFiles {
            dataset_dir,
            credentials_file,
            location_file,
        }
    }
}

struct ApplicationFiles {
    pub application_dir: PathBuf,

    pub location_file: PathBuf,
}

impl ApplicationFiles {
    pub fn new(name: &str, port: &str) -> Self {
        let dir = format!(application_dir!(), port, name);
        let application_dir = Path::new(&dir).to_path_buf();
        let location_file = application_dir.join(LOCATION_FILE);

        ApplicationFiles {
            application_dir,
            location_file,
        }
    }
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

pub trait ApplicationConfiguration {
    fn runtime_config_api(&self) -> &Box<dyn RuntimeConfiguration>;

    fn dataset_api(&self) -> &Box<dyn SdkmsDataset>;
}

pub struct EmAppApplicationConfiguration {
    pub runtime_config_api: Box<dyn RuntimeConfiguration>,

    pub dataset_api: Box<dyn SdkmsDataset>,
}

impl EmAppApplicationConfiguration {
    pub fn new() -> Self {
        EmAppApplicationConfiguration {
            runtime_config_api: Box::new(EmAppRuntimeConfiguration {}),
            dataset_api: Box::new(EmAppSdkmsDataset {}),
        }
    }
}

impl ApplicationConfiguration for EmAppApplicationConfiguration {
    fn runtime_config_api(&self) -> &Box<dyn RuntimeConfiguration> {
        &self.runtime_config_api
    }

    fn dataset_api(&self) -> &Box<dyn SdkmsDataset> {
        &self.dataset_api
    }
}

struct EmAppRuntimeConfiguration {}

impl RuntimeConfiguration for EmAppRuntimeConfiguration {
    fn get_runtime_configuration(
        &self,
        ccm_backend_url: &CCMBackendUrl,
        credentials: &EmAppCredentials,
    ) -> Result<RuntimeAppConfig, String> {
        em_app::utils::get_runtime_configuration(
            &ccm_backend_url.host,
            ccm_backend_url.port,
            credentials.certificate.clone(),
            credentials.key.clone(),
            credentials.root_certificate.clone(),
            None,
        )
    }
}

pub trait RuntimeConfiguration {
    fn get_runtime_configuration(
        &self,
        ccm_backend_url: &CCMBackendUrl,
        credentials: &EmAppCredentials,
    ) -> Result<RuntimeAppConfig, String>;
}

struct EmAppSdkmsDataset {}

impl SdkmsDataset for EmAppSdkmsDataset {
    fn get_dataset(
        &self,
        sdkms_credentials: &ApplicationConfigSdkmsCredentials,
        credentials: &EmAppCredentials,
    ) -> Result<Blob, String> {
        em_app::utils::get_sdkms_dataset(
            sdkms_credentials.credentials_url.clone(),
            sdkms_credentials.credentials_key_name.clone(),
            sdkms_credentials.sdkms_app_id,
            credentials.certificate.clone(),
            credentials.key.clone(),
            credentials.root_certificate.clone(),
            None,
        )
    }
}

pub trait SdkmsDataset {
    fn get_dataset(
        &self,
        sdkms_credentials: &ApplicationConfigSdkmsCredentials,
        credentials: &EmAppCredentials,
    ) -> Result<Blob, String>;
}

pub struct EmAppCredentials {
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

    #[cfg(test)]
    fn mock() -> Self {
        let key = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAh1aoz6wFwVHaCVDISSy+dZ8rOsJmfYBCrgzUjX+VNb2RwdT8
xv5fF0j0IXq+fKBShdZA+WGEQd6BMU0fqc2o7ACLvPWbvdKrLcwWpnL/UpFV8PxJ
yLemR8CBkGYcN2EJHhRhZcAGMBKwR1lI+ymOPJz4+nyDWVh9ttrvkKZU9b59zDkP
ET6PDJb5x9+fd41laQVOLvwlF4Xrl0b0DakXF3BVYpJIJ+b51QnMnwQ2xHVybFlZ
ONBwv1h52Xy7chvx79zPXzxZFbEc0phIhRqenv0/6/8HxpqqctSs9HHUn5A+4d/o
955ki8ZB1Nl5EuY+S59HzdsnQXR+OZxt3PxjTQIDAQABAoIBAANfW3UaPdfOTFqh
S5jXNbUhFgp3sa2ufaWMraHvQYPwM9Vo6KSIXGleIZV7/jVo0x6BVry1e2ICmMGR
FjWSIqAkPuVp36DD+9QGU+zVBan9SSgTD5SFh+4dzNWfOVRVSSJu+c13hKG70e5/
5KLKDvmKXSye/Ftg8VuysWmS6bxolGm86b+tltQ95V2qgim41MpaOUzilf1sDc5A
3hnorZvxH+kbMSGTRBdlPX54dux0SlT+o7sh9ig2sPJKkevnHeWd6nEeyeVYzP05
vH5yXirYb1CttPb5tqLcNCKRgawR5ByMMycn8bRSHScxyCLKco++JWL7L8hmcFTM
qFqCa9kCgYEAunw/Qofipch+bcMDsNmd6d9s9l1bBpXkP1ARQohuoVpsJITg+CH6
Dm3tWHnawwCxuQEUZ1/2cqZtrDBukgC90HK0H5j6b8FfyQ0mS3OOnqBHnhV66AXM
Hzlin1Vgaqwuhooy/CfOAyqpMqAfCgCAscxs6EOMteYrY+Xy7Ou02fMCgYEAucme
nNMsSElhsQwW7xpz8rr4k3THKSoetg2pbaUwXR4XDz/J1XWCIkSo8RuN1hA+z6+a
GzJa7CozmaM1j7aGo91U/LN/aNZ9etEbDOO+WCU/K0uTFtVAwgivRqETMARzEvuy
r1M2amUUDM5pX8Jk/Q19cGXQdyJdpShqp8Y93b8CgYEAhukkCsmrmiv16wpOPT7y
EyPj/EeFdroxqewO0IdLIcf8vF61Mk3CTXYRYxSkwrZZ3HF/hVnTPRZR+WQAWffX
WlnhHYragsbuuNCeh69N2kwyA5eelwS6q0wkoQhu/D0cW5DXWbyiOYA/b7SPP/kl
IXu2vkFAJsghU+AjYmsTJykCgYBtuzvHfKKG/3CH1ZAmIQWis/Plg++tzIbfGCqd
7BcoqIEOLKrVPNZjzxHJdnDLokS2/gyTS6aQHkzjzZXxD+luF2f+6TWzghwS0jab
4lemUDmDJNv3fHUHJYIAwVpH3hjpeWgMTaWyKYkyFyf9ux9SpwkTvc7mzpFo3vo/
pcMcmQKBgCVZpfRJxJ1pc4v0M2pxF3zsyDo3CbvhO7ZjOwYyNa5A+p65BsGbOjuR
2v6GLNvYtgqM+FXqTyqz2RkyoKIOqXyOWdSDPHaP2mu5A0xaTom6H7F8PuNFIm4F
iy6KC991zzvaWY/Ys+q/84Afqa+0qJKQnPuy/7F5GkVdQA/lfbhi
-----END RSA PRIVATE KEY-----
\0";

        let pk = Pk::from_private_key(key.as_bytes(), None).unwrap();

        let cert_list = MbedtlsList::<Certificate>::new();

        EmAppCredentials {
            certificate: Arc::new(cert_list),
            key: Arc::new(pk),
            root_certificate: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use em_app::utils::models::{
        ApplicationConfigConnection, ApplicationConfigConnectionApplication, ApplicationConfigConnectionDataset,
        ApplicationConfigDatasetCredentials, ApplicationConfigExtra, ApplicationConfigSdkmsCredentials,
    };
    use sdkms::api_model::Blob;

    use crate::app_configuration::{setup_datasets, ApplicationFiles, DataSetFiles, EmAppCredentials, SdkmsDataset};

    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;

    struct TempDir<'a>(pub &'a Path);

    impl<'a> Drop for TempDir<'a> {
        fn drop(&mut self) {
            fs::remove_dir_all(self.0).expect(&format!("Failed deleting path {}", self.0.display()));
        }
    }

    struct MockDataSet {}

    impl SdkmsDataset for MockDataSet {
        fn get_dataset(
            &self,
            _sdkms_credentials: &ApplicationConfigSdkmsCredentials,
            _credentials: &EmAppCredentials,
        ) -> Result<Blob, String> {
            Ok(Blob::from("OK"))
        }
    }

    #[test]
    fn setup_datasets_should_fail_when_no_connections_are_present() {
        let config = ApplicationConfigExtra { connections: None };
        let credentials = EmAppCredentials::mock();
        let api: Box<dyn SdkmsDataset> = Box::new(MockDataSet {});

        let result = setup_datasets(&config, &credentials, &api);
        assert!(
            result.is_err(),
            "setup_datasets should return error if there are no connections in ApplicationConfigExtra"
        )
    }

    #[test]
    fn setup_credentials_correct_pass() {
        let config = {
            let mut connections: BTreeMap<String, BTreeMap<String, ApplicationConfigConnection>> = BTreeMap::new();
            let mut app_config: BTreeMap<String, ApplicationConfigConnection> = BTreeMap::new();
            let dataset = ApplicationConfigConnectionDataset {
                location: "www.test.com".to_string(),
                credentials: ApplicationConfigDatasetCredentials {
                    sdkms: Some(ApplicationConfigSdkmsCredentials {
                        credentials_url: "url".to_string(),
                        credentials_key_name: "key-name".to_string(),
                        sdkms_app_id: Default::default(),
                    }),
                },
            };

            let connection = ApplicationConfigConnection {
                dataset: Some(dataset),
                application: None,
            };

            app_config.insert("test_location".to_string(), connection);
            connections.insert("test_port".to_string(), app_config);

            ApplicationConfigExtra {
                connections: Some(connections),
            }
        };

        let credentials = EmAppCredentials::mock();
        let api: Box<dyn SdkmsDataset> = Box::new(MockDataSet {});

        let files = DataSetFiles::new("test_location", "test_port");
        let _temp_dir = TempDir(&files.dataset_dir);

        let result = setup_datasets(&config, &credentials, &api);
        assert!(result.is_ok(), "{:?}", result);

        let credentials = fs::read_to_string(&files.credentials_file).expect("Failed reading credentials file");
        let location = fs::read_to_string(&files.location_file).expect("Failed reading locations file");

        assert_eq!(credentials, "OK");
        assert_eq!(location, "www.test.com");
    }

    #[test]
    fn setup_application_location_correct_pass() {
        let config = {
            let mut connections: BTreeMap<String, BTreeMap<String, ApplicationConfigConnection>> = BTreeMap::new();
            let mut app_config: BTreeMap<String, ApplicationConfigConnection> = BTreeMap::new();
            let application = ApplicationConfigConnectionApplication {
                workflow_domain: "test_workflow".to_string(),
            };

            let connection = ApplicationConfigConnection {
                dataset: None,
                application: Some(application),
            };

            app_config.insert("test_location".to_string(), connection);
            connections.insert("test_port".to_string(), app_config);

            ApplicationConfigExtra {
                connections: Some(connections),
            }
        };

        let credentials = EmAppCredentials::mock();
        let api: Box<dyn SdkmsDataset> = Box::new(MockDataSet {});

        let files = ApplicationFiles::new("test_location", "test_port");
        let _temp_dir = TempDir(&files.application_dir);

        let result = setup_datasets(&config, &credentials, &api);
        assert!(result.is_ok(), "{:?}", result);

        let location = fs::read_to_string(&files.location_file).expect("Failed reading locations file");

        assert_eq!(location, "test_workflow");
    }
}
