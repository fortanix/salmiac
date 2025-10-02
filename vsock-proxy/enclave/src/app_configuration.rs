/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use api_model::enclave::CcmBackendUrl;
use em_app::utils::models::{
    ApplicationConfigContents, ApplicationConfigExtra, ApplicationConfigSdkmsCredentials, RuntimeAppConfig,
};
use em_client::Sha256Hash;
use log::{info, warn};
use mbedtls::alloc::List as MbedtlsList;
use mbedtls::pk::Pk;
use mbedtls::x509::Certificate;
use sdkms::api_model::Blob;

use crate::certificate::CertificateResult;
use crate::enclave::write_to_file;

// All of the paths below are purposefully made relative because they are joined with the path pointing to the chroot environment.
pub const APPLICATION_CONFIG_DIR: &str = "opt/fortanix/enclave-os/app-config/rw";
pub const APPLICATION_CONFIG_FILE: &str = "opt/fortanix/enclave-os/app-config/rw/app-config.json";

macro_rules! dataset_dir {
    () => {
        "opt/fortanix/enclave-os/app-config/rw/{}/{}/dataset"
    };
}

macro_rules! application_dir {
    () => {
        "opt/fortanix/enclave-os/app-config/rw/{}/{}/application"
    };
}

const CREDENTIALS_FILE: &str = "credentials.bin";

const LOCATION_FILE: &str = "location.txt";

pub(crate) fn setup_application_configuration<T>(
    em_app_credentials: &EmAppCredentials,
    ccm_backend_url: &CcmBackendUrl,
    api: T,
    fs_root: &Path,
    app_config_id: &Sha256Hash,
) -> Result<(), String>
where
    T: ApplicationConfiguration,
{
    info!("Requesting application configuration.");

    let app_config = api
        .runtime_config_api()
        .get_runtime_configuration(&ccm_backend_url, em_app_credentials, app_config_id)?;

    write_runtime_configuration_to_file(&app_config, fs_root)?;

    setup_datasets(&app_config.extra, em_app_credentials, api.dataset_api(), fs_root)?;

    setup_app_configs(&app_config.config.app_config, fs_root)
}

fn write_runtime_configuration_to_file(app_config: &RuntimeAppConfig, fs_root: &Path) -> Result<(), String> {
    let data =
        serde_json::to_string(app_config).map_err(|err| format!("Failed serializing app config to string. {:?}", err))?;

    fs::create_dir_all(fs_root.join(Path::new(APPLICATION_CONFIG_DIR)))
        .map_err(|err| format!("Failed to create app config directory. {:?}", err))?;

    write_to_file(&fs_root.join(Path::new(APPLICATION_CONFIG_FILE)), &data, "application config")?;

    Ok(())
}

fn setup_datasets<T>(
    config: &ApplicationConfigExtra,
    credentials: &EmAppCredentials,
    api: &T,
    fs_root: &Path,
) -> Result<(), String>
where
    T: SdkmsDataset,
{
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

                    let files = DataSetFiles::new(name, port, fs_root);

                    fs::create_dir_all(&files.dataset_dir)
                        .map_err(|err| format!("Failed to create data set directory. {:?}", err))?;

                    write_to_file(&files.credentials_file, &response, "data set")?;
                    write_to_file(&files.location_file, &dataset.location, "location")?;
                }
            } else if let Some(application) = &object.application {
                let files = ApplicationFiles::new(name, port, fs_root);

                fs::create_dir_all(&files.application_dir)
                    .map_err(|err| format!("Failed to create application directory. {:?}", err))?;

                write_to_file(&files.location_file, &application.workflow_domain, "workflow domain")?;
            }
        }
    }

    Ok(())
}

fn setup_app_configs(config_map: &BTreeMap<String, ApplicationConfigContents>, fs_root: &Path) -> Result<(), String> {
    for (file, contents_opt) in config_map {
        let file_path = normalize_path_and_make_relative(&file)
            .map_err(|err| format!("Cannot normalize file path in application config. {}", err))?;

        if !file_path.starts_with(APPLICATION_CONFIG_DIR) {
            return Err(format!(
                "Invalid application config detected. Config file {} must point to {} dir",
                file, APPLICATION_CONFIG_DIR
            ));
        }

        let dir = file_path.parent().ok_or(format!(
            "Invalid application config detected. Config file {} must have a directory part",
            file
        ))?;

        fs::create_dir_all(fs_root.join(dir)).map_err(|err| format!("Failed to create dir for file {}. {:?}", file, err))?;

        if let Some(encoded_contents) = &contents_opt.contents {
            let decoded_contents = base64::decode(encoded_contents)
                .map_err(|err| format!("Failed to base64 decode application config contents. {:?}", err))?;

            write_to_file(&fs_root.join(file_path), &decoded_contents, "application config contents")?;
        } else {
            warn!(
                "Found application config {} with no contents. Created file will be empty.",
                file
            )
        }
    }

    Ok(())
}

struct DataSetFiles {
    dataset_dir: PathBuf,

    credentials_file: PathBuf,

    location_file: PathBuf,
}

impl DataSetFiles {
    fn new(name: &str, port: &str, fs_root: &Path) -> Self {
        let dir = format!(dataset_dir!(), port, name);
        let dataset_dir = fs_root.join(Path::new(&dir));
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
    application_dir: PathBuf,

    location_file: PathBuf,
}

impl ApplicationFiles {
    fn new(name: &str, port: &str, fs_root: &Path) -> Self {
        let dir = format!(application_dir!(), port, name);
        let application_dir = fs_root.join(Path::new(&dir));
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

fn normalize_path_and_make_relative(raw_path: &str) -> Result<PathBuf, String> {
    if raw_path.ends_with("/") || raw_path.ends_with("/.") {
        return Err(format!("Can't normalize path {}. The path ends with '/' or '/.'.", raw_path));
    }

    let path = Path::new(raw_path);

    if !path.has_root() {
        return Err(format!("Can't normalize path {}. Path must be absolute. ", path.display()));
    }

    // We remove the root ("/") to make the path relative so that it can be joined with the path pointing to the chroot environment
    // forming a correct path to the workflow data
    let mut result = PathBuf::new();

    for component in path.components() {
        match component {
            Component::RootDir => (),
            Component::Normal(folder) => result.push(folder),
            Component::ParentDir => {
                return Err(format!(
                    "Can't normalize path {}. Parent dir (..) symbol is not supported.",
                    path.display()
                ));
            }
            Component::Prefix(_) => {
                panic!(
                    "Prefix should not be present in path normalization. Application config path is {}",
                    path.display()
                );
            }
            Component::CurDir => {
                return Err(format!(
                    "Can't normalize path {}. Current dir in path is not supported.",
                    path.display()
                ));
            }
        }
    }

    Ok(result)
}

pub(crate) trait ApplicationConfiguration {
    type R: RuntimeConfiguration;

    type S: SdkmsDataset;

    fn runtime_config_api(&self) -> &Self::R;

    fn dataset_api(&self) -> &Self::S;
}

pub(crate) struct EmAppApplicationConfiguration {
    pub runtime_config_api: EmAppRuntimeConfiguration,

    pub dataset_api: EmAppSdkmsDataset,
}

impl EmAppApplicationConfiguration {
    pub(crate) fn new() -> Self {
        EmAppApplicationConfiguration {
            runtime_config_api: EmAppRuntimeConfiguration {},
            dataset_api: EmAppSdkmsDataset {},
        }
    }
}

impl ApplicationConfiguration for EmAppApplicationConfiguration {
    type R = EmAppRuntimeConfiguration;

    type S = EmAppSdkmsDataset;

    fn runtime_config_api(&self) -> &EmAppRuntimeConfiguration {
        &self.runtime_config_api
    }

    fn dataset_api(&self) -> &EmAppSdkmsDataset {
        &self.dataset_api
    }
}

pub(crate) struct EmAppRuntimeConfiguration {}

impl RuntimeConfiguration for EmAppRuntimeConfiguration {
    fn get_runtime_configuration(
        &self,
        ccm_backend_url: &CcmBackendUrl,
        credentials: &EmAppCredentials,
        expected_hash: &Sha256Hash,
    ) -> Result<RuntimeAppConfig, String> {
        em_app::utils::get_runtime_configuration(
            &ccm_backend_url.host,
            ccm_backend_url.port,
            credentials.certificate.clone(),
            credentials.key.clone(),
            credentials.root_certificate.clone(),
            None,
            &expected_hash,
        )
    }
}

pub(crate) trait RuntimeConfiguration {
    fn get_runtime_configuration(
        &self,
        ccm_backend_url: &CcmBackendUrl,
        credentials: &EmAppCredentials,
        expected_hash: &Sha256Hash,
    ) -> Result<RuntimeAppConfig, String>;
}

pub(crate) struct EmAppSdkmsDataset {}

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

pub(crate) trait SdkmsDataset {
    fn get_dataset(
        &self,
        sdkms_credentials: &ApplicationConfigSdkmsCredentials,
        credentials: &EmAppCredentials,
    ) -> Result<Blob, String>;
}

pub(crate) struct EmAppCredentials {
    certificate: Arc<MbedtlsList<Certificate>>,

    key: Arc<Pk>,

    root_certificate: Option<Arc<MbedtlsList<Certificate>>>,
}

impl EmAppCredentials {
    pub(crate) fn new(mut certificate_info: CertificateResult, skip_server_verify: bool) -> Result<Self, String> {
        let certificate = {
            certificate_info.certificate.push('\0');

            let app_cert = Certificate::from_pem_multiple(&certificate_info.certificate.as_bytes())
                .map_err(|e| format!("Parsing certificate failed: {:?}", e))?;

            Arc::new(app_cert)
        };

        // The private key from certificate info can't be copied/cloned, thus we use mbedtls
        // library functions to convert it into DER buffer and create a Pk from it.
        let der_buf = certificate_info.key.write_private_der_vec().unwrap();
        let dup_pk = Pk::from_private_key(&*der_buf, None).unwrap();
        let key = Arc::new(dup_pk);

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
    use std::collections::BTreeMap;
    use std::convert::TryFrom;
    use std::fs;
    use std::path::Path;

    use api_model::enclave::CcmBackendUrl;
    use em_app::utils::models::{
        ApplicationConfigConnection, ApplicationConfigConnectionApplication, ApplicationConfigConnectionDataset,
        ApplicationConfigDatasetCredentials, ApplicationConfigExtra, ApplicationConfigSdkmsCredentials, RuntimeAppConfig,
    };
    use sdkms::api_model::Blob;

    use crate::app_configuration::{
        normalize_path_and_make_relative, setup_app_configs, setup_datasets, ApplicationConfiguration, ApplicationFiles,
        DataSetFiles, EmAppCredentials, RuntimeConfiguration, SdkmsDataset, Sha256Hash,
    };

    const TEST_FOLDER: &'static str = "/tmp/salm-unit-test";

    const VALID_RUNTIME_CONF: &'static str = "\
    {
        \"config\": {
            \"app_config\": {
                \"path\": {
				    \"contents\": \"contents\"
			    }
            },
		    \"labels\": {
			    \"location\": \"East US\"
		    },
		    \"zone_ca\": [\"cert\"],
            \"workflow\": {
                \"workflow_id\": \"35de225c-cfef-4f1b-b0bc-287b58f55244\",
                \"app_name\": \"app-1\",
                \"port_map\": {
                    \"input\": {
                        \"input-1\": {
                            \"dataset\": {
                                \"id\": \"611ff8ce-3cc7-4f26-8a28-4327446cd800\"
                            }
                        }
                    },
                    \"output\": {
                        \"output-1\": {
                            \"dataset\": {
                                \"id\": \"7dda9870-b394-4ff2-aa73-e9971b1857f9\"
                            }
                        }
                    }
                }
		    }
        },
        \"extra\": {
            \"connections\": {
                \"input\": {
                    \"input-1\": {
                        \"dataset\": {
                            \"location\": \"https://path/to/test\",
                            \"credentials\": {
                                \"sdkms\": {
                                    \"credentials_url\": \"https://apps.sdkms.test.fortanix.com\",
                                    \"credentials_key_name\": \"611ff8ce-3cc7-4f26-8a28-4327446cd800-credentials\",
                                    \"sdkms_app_id\": \"8afcd4d6-2483-4a68-bc92-0ec53a4e97dc\"
                                }
                            }
                        }
                    }
                },
                \"output\": {
                    \"output-1\": {
                        \"dataset\": {
                            \"location\": \"https://path/to/test\",
                            \"credentials\": {
                                \"sdkms\": {
                                    \"credentials_url\": \"https://apps.sdkms.test.fortanix.com\",
                                    \"credentials_key_name\": \"7dda9870-b394-4ff2-aa73-e9971b1857f9-credentials\",
                                    \"sdkms_app_id\": \"8afcd4d6-2483-4a68-bc92-0ec53a4e97dc\"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    ";

    const VALID_APP_CONF: &'static str = "\
    {
        \"config\": {
            \"app_config\": {
                \"/opt/fortanix/enclave-os/app-config/rw/app_conf.txt\": {
				    \"contents\": \"SGVsbG8gV29ybGQ=\"
			    }
            },
		    \"labels\": {
			    \"location\": \"East US\"
		    },
		    \"zone_ca\": [\"cert\"]
        },
        \"extra\": { }
    }
    ";

    const VALID_APP_CONF_ADDITIONAL_FOLDER: &'static str = "\
    {
        \"config\": {
            \"app_config\": {
                \"/opt/fortanix/enclave-os/app-config/rw/folder/app_conf.txt\": {
				    \"contents\": \"RGVhZCBCZWVm\"
			    }
            },
		    \"labels\": {
			    \"location\": \"East US\"
		    },
		    \"zone_ca\": [\"cert\"]
        },
        \"extra\": { }
    }
    ";

    const APP_CONF_INCORRECT_FILE_PATH: &'static str = "\
    {
        \"config\": {
            \"app_config\": {
                \"/opt/my/personal/folder/app_conf.txt\": {
				    \"contents\": \"QkFBQUFBQUQ=\"
			    }
            },
		    \"labels\": {
			    \"location\": \"East US\"
		    },
		    \"zone_ca\": [\"cert\"]
        },
        \"extra\": { }
    }
    ";

    struct TempDir<'a>(pub &'a Path);

    impl<'a> Drop for TempDir<'a> {
        fn drop(&mut self) {
            fs::remove_dir_all(self.0).expect(&format!("Failed deleting path {}", self.0.display()));
        }
    }

    struct MockDataSet {
        pub json_data: &'static str,
        pub hash: Sha256Hash,
    }

    impl MockDataSet {
        fn application_config_extra() -> ApplicationConfigExtra {
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
        }
    }

    impl RuntimeConfiguration for MockDataSet {
        fn get_runtime_configuration(
            &self,
            _ccm_backend_url: &CcmBackendUrl,
            _credentials: &EmAppCredentials,
            expected_hash: &Sha256Hash,
        ) -> Result<RuntimeAppConfig, String> {
            if self.hash != *expected_hash {
                Err(format!(
                    "Expected hash: {:?} doesn't equal saved hash: {:?}",
                    expected_hash, self.hash
                ))
            } else {
                Ok(serde_json::from_str(self.json_data).expect("Failed serializing test json"))
            }
        }
    }

    impl SdkmsDataset for MockDataSet {
        fn get_dataset(
            &self,
            _sdkms_credentials: &ApplicationConfigSdkmsCredentials,
            _credentials: &EmAppCredentials,
        ) -> Result<Blob, String> {
            Ok(Blob::from("OK"))
        }
    }

    impl ApplicationConfiguration for MockDataSet {
        type R = Self;
        type S = Self;

        fn runtime_config_api(&self) -> &Self::R {
            &self
        }

        fn dataset_api(&self) -> &Self::S {
            &self
        }
    }

    #[test]
    fn setup_runtime_config_correct_json() {
        let config: RuntimeAppConfig = run_setup_runtime_configuration(VALID_RUNTIME_CONF);

        let reference: RuntimeAppConfig = serde_json::from_str(VALID_RUNTIME_CONF).expect("Failed serializing test json");

        assert_eq!(config, reference);
    }

    fn run_setup_runtime_configuration(json_data: &'static str) -> RuntimeAppConfig {
        let backend_url = CcmBackendUrl {
            host: String::new(),
            port: 0,
        };

        let credentials = EmAppCredentials::mock();
        let api: Box<dyn RuntimeConfiguration> = Box::new(MockDataSet {
            json_data,
            hash: Sha256Hash::try_from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap(),
        });

        let result = api.get_runtime_configuration(
            &backend_url,
            &credentials,
            &Sha256Hash::try_from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap(),
        );
        assert!(result.is_ok(), "{:?}", result);

        result.unwrap()
    }

    #[test]
    fn setup_datasets_should_fail_when_no_connections_are_present() {
        let config = ApplicationConfigExtra { connections: None };
        let credentials = EmAppCredentials::mock();
        let api = MockDataSet {
            json_data: VALID_APP_CONF,
            hash: Sha256Hash::try_from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap(),
        };

        let result = setup_datasets(&config, &credentials, &api, Path::new("/"));
        assert!(
            result.is_err(),
            "setup_datasets should return error if there are no connections in ApplicationConfigExtra"
        )
    }

    #[test]
    fn setup_data_sets_correct_pass() {
        let config = MockDataSet::application_config_extra();

        let credentials = EmAppCredentials::mock();
        let api = MockDataSet {
            json_data: VALID_APP_CONF,
            hash: Sha256Hash::try_from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap(),
        };

        let test_folder_path = Path::new(TEST_FOLDER).join("datasets");
        let test_folder = TempDir(&test_folder_path);
        let files = DataSetFiles::new("test_location", "test_port", test_folder.0);
        let _temp_dataset_dir = TempDir(&files.dataset_dir);

        let result = setup_datasets(&config, &credentials, &api, &test_folder.0);
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
        let api = MockDataSet {
            json_data: VALID_APP_CONF,
            hash: Sha256Hash::try_from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap(),
        };

        let test_folder_path = Path::new(TEST_FOLDER).join("appconfig-location");
        let test_folder = TempDir(&test_folder_path);

        let files = ApplicationFiles::new("test_location", "test_port", &test_folder.0);
        let _temp_dir = TempDir(&files.application_dir);

        let result = setup_datasets(&config, &credentials, &api, &test_folder.0);
        assert!(result.is_ok(), "{:?}", result);

        let location = fs::read_to_string(&files.location_file).expect("Failed reading locations file");

        assert_eq!(location, "test_workflow");
    }

    #[test]
    fn setup_application_configurations_correct_pass() {
        let runtime_config: RuntimeAppConfig = run_setup_runtime_configuration(VALID_APP_CONF);
        let test_folder_path = Path::new(TEST_FOLDER).join("appconfig");
        let test_folder = TempDir(&test_folder_path);

        assert_eq!(runtime_config.config.app_config.is_empty(), false);

        setup_app_configs(&runtime_config.config.app_config, &test_folder.0).expect("Failed setting up runtime app config");

        let result = fs::read_to_string(test_folder.0.join("opt/fortanix/enclave-os/app-config/rw/app_conf.txt"))
            .expect("Failed reading app config file");

        assert_eq!(result, "Hello World")
    }

    #[test]
    fn setup_application_configurations_additional_folder_correct_pass() {
        let runtime_config: RuntimeAppConfig = run_setup_runtime_configuration(VALID_APP_CONF_ADDITIONAL_FOLDER);
        let test_folder_path = Path::new(TEST_FOLDER).join("appconfig-additional-folder");
        let test_folder = TempDir(&test_folder_path);

        assert_eq!(runtime_config.config.app_config.is_empty(), false);

        setup_app_configs(&runtime_config.config.app_config, &test_folder.0).expect("Failed setting up runtime app config");

        let result = fs::read_to_string(
            &test_folder
                .0
                .join("opt/fortanix/enclave-os/app-config/rw/folder/app_conf.txt"),
        )
        .expect("Failed reading app config file");

        assert_eq!(result, "Dead Beef")
    }

    #[test]
    fn setup_application_configurations_incorrect_file_path() {
        let runtime_config: RuntimeAppConfig = run_setup_runtime_configuration(APP_CONF_INCORRECT_FILE_PATH);

        assert_eq!(runtime_config.config.app_config.is_empty(), false);

        assert!(setup_app_configs(&runtime_config.config.app_config, Path::new("/")).is_err());
    }

    #[test]
    fn normalize_path_correct_pass() {
        assert_eq!(
            Path::new("❤/✈/☆"),
            normalize_path_and_make_relative("/❤/✈/☆").unwrap().as_path()
        );
        assert_eq!(
            Path::new("air/✈/plane"),
            normalize_path_and_make_relative("/air/✈/plane").unwrap().as_path()
        );

        assert_eq!(
            Path::new("a/b"),
            normalize_path_and_make_relative("/a////b").unwrap().as_path()
        );
        assert_eq!(
            Path::new("a/b"),
            normalize_path_and_make_relative("/a/./././b").unwrap().as_path()
        );
        assert_eq!(Path::new("..."), normalize_path_and_make_relative("/...").unwrap().as_path());
        assert_eq!(Path::new("a."), normalize_path_and_make_relative("/a.").unwrap().as_path());
        assert_eq!(Path::new("a.."), normalize_path_and_make_relative("/a..").unwrap().as_path());

        assert_eq!(
            Path::new("a/b/d/c"),
            normalize_path_and_make_relative("/a//.///b/d/.///./c").unwrap().as_path()
        );

        assert!(normalize_path_and_make_relative("a/b/c").is_err());
        assert!(normalize_path_and_make_relative("/.").is_err());
        assert!(normalize_path_and_make_relative("/a/../b").is_err());
        assert!(normalize_path_and_make_relative("/a/b/c/").is_err());
        assert!(normalize_path_and_make_relative("/a/b/c/.").is_err());
        assert!(normalize_path_and_make_relative("/a/b/c/..").is_err());
    }
}
