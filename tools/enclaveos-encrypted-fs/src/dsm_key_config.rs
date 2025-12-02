/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::CString;
use std::string::ToString;
use std::sync::{Arc, Mutex};

use em_app::mbedtls_hyper::MbedSSLClient;
use hyper::client::Pool;
use hyper::net::HttpsConnector;
use hyper::Client;
use log::info;
use mbedtls::pk::Pk;
use mbedtls::ssl::config::{AuthMode, Endpoint, Preset, Transport};
use mbedtls::ssl::{Config, Version};
use mbedtls::x509::Certificate;
use sdkms::api_model::{
    Algorithm, Blob, CipherMode, CryptMode, DecryptRequest, DeriveKeyMechanism, DeriveKeyRequest, DigestAlgorithm,
    EncryptRequest, KeyOperations, ListSobjectsParams, MacRequest, ObjectType, Sobject, SobjectDescriptor, VerifyMacRequest,
};
use sdkms::SdkmsClient;
use uuid::Uuid;

use crate::utils::find_env_or_err;

pub const DEFAULT_DSM_ENDPOINT: &str = "https://amer.smartkey.io/";
pub const DEFAULT_DSM_APPS_ENDPOINT: &str = "https://apps.amer.smartkey.io/";

pub struct ClientCertificate {
    pub certificate: String,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EncryptedPassphrase {
    pub key: Blob,
    pub iv: Blob,
    pub tag: Blob,
}

/// Information needed to connect to DSM as a client
pub struct ClientConnectionInfo<'a> {
    pub fs_api_key: Option<String>,
    pub auth_cert: Option<&'a mut ClientCertificate>,
    pub dsm_url: String,
}

#[derive(Clone)]
pub struct DsmFsOps {
    client: Arc<Mutex<SdkmsClient>>,
    sobject_prefix: String,
    derivation_data_iv: String,
}

impl DsmFsOps {
    fn create_client(conn_info: ClientConnectionInfo) -> Result<SdkmsClient, String> {
        info!("Looking for API key needed to create DSM client.");
        let api_key = conn_info.fs_api_key.unwrap_or_default();

        if api_key.is_empty() {
            info!("Using app cert for auth with DSM");

            let app_id_str = find_env_or_err("DSM_APP_ID").unwrap_or_default();
            let app_id = Uuid::parse_str(&app_id_str).ok();

            let endpoint = conn_info.dsm_url;
            let endoint_url = url::Url::parse(&*endpoint).map_err(|e| format!("Unable to parse endpoint : {:?}", e))?;
            let host = endoint_url
                .host_str()
                .ok_or_else(|| format!("Unable to get host from endpoint"))?;
            let hyper_client = Self::create_hyper_client_with_cert(
                host.to_string(),
                conn_info
                    .auth_cert
                    .ok_or_else(|| format!("Unable to get auth cert for connection to DSM"))?,
            )?;

            Ok(SdkmsClient::builder()
                .with_hyper_client(hyper_client)
                .with_api_endpoint(&*endpoint)
                .build()
                .map_err(|_| format!("DSM client build failed"))?
                .authenticate_with_cert(app_id.as_ref())
                .map_err(|_| format!("Unable to auth with app cert"))?)
        } else {
            info!("Using API key for auth with DSM");
            let endpoint = conn_info.dsm_url;
            // Note - mapping an empty error here, mapping an error type results in a hang
            // Needs to be investigated.
            Ok(SdkmsClient::builder()
                .with_api_endpoint(&endpoint)
                .build()
                .map_err(|_| format!("DSM client build failed"))?
                .authenticate_with_api_key(&*api_key)
                .map_err(|_| format!("Unable to auth with api key"))?)
        }
    }

    fn create_hyper_client_with_cert(host: String, auth_cert: &mut ClientCertificate) -> Result<Arc<Client>, String> {
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_authmode(AuthMode::Optional);
        config.set_rng(Arc::new(mbedtls::rng::Rdrand));
        config
            .set_min_version(Self::TLS_MIN_VERSION)
            .map_err(|e| format!("TLS configuration failed: {:?}", e))?;

        let cert = {
            let cert_pem = CString::new(&*auth_cert.certificate)
                .map_err(|e| format!("Can't create cstring from cert pem {:?}", e.to_string()))?;
            let app_cert = Certificate::from_pem_multiple(cert_pem.as_bytes_with_nul())
                .map_err(|e| format!("Parsing certificate failed: {:?}", e))?;

            Arc::new(app_cert)
        };

        let der_key = auth_cert.key.clone();
        let pk_key = Pk::from_private_key(&*der_key, None)
            .map_err(|e| format!("Failed creating private key from der format. {:?}", e))?;
        let key = Arc::new(pk_key);

        config
            .push_cert(cert, key)
            .map_err(|e| format!("TLS configuration failed: {:?}", e))?;

        let ssl = MbedSSLClient::new_with_sni(Arc::new(config), true, Some(host));
        let connector = HttpsConnector::new(ssl);
        Ok(Arc::new(hyper::Client::with_connector(Pool::with_connector(
            Default::default(),
            connector,
        ))))
    }

    fn get_keys(client: &SdkmsClient, query_params: Option<&ListSobjectsParams>) -> Result<Vec<Sobject>, String> {
        client
            .list_sobjects(query_params)
            .map_err(|_| format!("Unable to list sobjects"))
    }

    fn get_key_by_prefix(client: &SdkmsClient, prefix: &str) -> Result<Sobject, String> {
        // res_key_list_len initialized to 1 to ensure we can enter the while loop,
        // after which its contents will be overwritten.
        let mut res_key_list_len = 1;
        let mut offset = 0;
        let mut result_key = vec![];
        while res_key_list_len > 0 {
            let query_params = ListSobjectsParams {
                group_id: None,
                creator: None,
                name: None,
                limit: Some(Self::SOBJECT_LIST_LIMIT),
                offset: Some(offset),
                sort: Default::default(),
            };
            let key_list = Self::get_keys(client, Some(&query_params))?;
            res_key_list_len = key_list.len();
            offset = offset + res_key_list_len;

            let mut prefixed_key = Self::filter_key_by_prefix(key_list, prefix);
            if prefixed_key.len() > 0 {
                result_key.append(&mut prefixed_key);
            }
        }
        if result_key.is_empty() {
            Err(format!("Unable to find key with prefix {:?}", prefix))
        } else if result_key.len() > 1 {
            Err(format!(
                "Unexpected behaviour - found {} keys with prefix {:?}",
                result_key.len(),
                prefix
            ))
        } else {
            Ok(result_key.get(0).expect("Unable to pop prefixed result key").clone())
        }
    }

    fn generate_derive_key_req(
        kid: SobjectDescriptor,
        key_ops: KeyOperations,
        derivation_data: &str,
        derivation_data_iv: String,
    ) -> DeriveKeyRequest {
        DeriveKeyRequest {
            activation_date: None,
            deactivation_date: None,
            key: Some(kid.clone()),
            name: None,
            group_id: None,
            key_type: ObjectType::Aes,
            key_size: Self::DERIVED_KEY_SIZE,
            mechanism: DeriveKeyMechanism::EncryptData(EncryptRequest {
                key: Some(kid),
                alg: Algorithm::Aes,
                plain: Blob::from(derivation_data),
                mode: Some(CryptMode::Symmetric(CipherMode::Cbc)),
                iv: Some(derivation_data_iv.into()),
                ad: None,
                tag_len: None,
            }),
            enabled: None,
            description: None,
            custom_metadata: None,
            key_ops: Some(key_ops),
            state: None,
            transient: Some(true),
        }
    }

    fn derive_mac_key(client: &SdkmsClient, sobject_prefix: String, derivation_data_iv: String) -> Result<Blob, String> {
        // Find the parent key by prefix name search
        let parent_key = Self::get_key_by_prefix(client, &sobject_prefix)?;
        let parent_kid = parent_key
            .kid
            .ok_or_else(|| format!("Unable to obtain parent key's ID for wrapping passphrase"))?;

        // Derive transient key
        let derive_key_req = Self::generate_derive_key_req(
            SobjectDescriptor::Kid(parent_kid),
            KeyOperations::MACGENERATE | KeyOperations::MACVERIFY,
            Self::DERIVATION_DATA_HEADER_HMAC,
            derivation_data_iv,
        );

        let transient_sobject = client
            .derive(&derive_key_req)
            .map_err(|e| format!("Unable to derive key : {:?}", e))?;

        transient_sobject
            .transient_key
            .ok_or_else(|| format!("Transient key blob not found in sobject"))
    }

    fn derive_enc_dec_key(client: &SdkmsClient, sobject_prefix: String, derivation_data_iv: String) -> Result<Blob, String> {
        // Find the parent key by prefix name search
        let parent_key = Self::get_key_by_prefix(client, &sobject_prefix)?;
        let parent_kid = parent_key
            .kid
            .ok_or_else(|| format!("Unable to obtain parent key's ID for wrapping passphrase"))?;

        // Derive transient key
        let derive_key_req = Self::generate_derive_key_req(
            SobjectDescriptor::Kid(parent_kid),
            KeyOperations::ENCRYPT | KeyOperations::DECRYPT,
            Self::DERIVATION_DATA_PASSPHRASE,
            derivation_data_iv,
        );

        let transient_sobject = client
            .derive(&derive_key_req)
            .map_err(|e| format!("Unable to derive key : {:?}", e))?;
        transient_sobject
            .transient_key
            .ok_or_else(|| format!("Transient key blob not found in sobject"))
    }

    fn mac_header(
        client: &SdkmsClient,
        header: Blob,
        sobject_prefix: String,
        derivation_data_iv: String,
    ) -> Result<Blob, String> {
        let transient_key = Self::derive_mac_key(client, sobject_prefix, derivation_data_iv)?;

        // Generate MAC with transient key
        let mac_request = MacRequest {
            key: Some(SobjectDescriptor::TransientKey(transient_key)),
            alg: Some(DigestAlgorithm::Sha256),
            data: header,
        };

        let mac_response = client
            .mac(&mac_request)
            .map_err(|e| format!("Unable to request MAC : {:?}", e))?;
        Ok(mac_response.mac)
    }

    fn mac_verify_header(
        client: &SdkmsClient,
        header: Blob,
        mac: Blob,
        sobject_prefix: String,
        derivation_data_iv: String,
    ) -> Result<(), String> {
        let transient_key = Self::derive_mac_key(client, sobject_prefix, derivation_data_iv)?;

        // MAC verify the header with transient key
        let macv_request = VerifyMacRequest {
            key: Some(SobjectDescriptor::TransientKey(transient_key)),
            alg: Some(DigestAlgorithm::Sha256),
            data: header,
            digest: None,
            mac: Some(mac),
        };
        let macv_response = client
            .mac_verify(&macv_request)
            .map_err(|e| format!("Unable to verify MAC : {:?}", e))?;
        macv_response.result.then(|| ()).ok_or("MAC verification failed".to_string())
    }

    fn encrypt_passphrase(
        client: &SdkmsClient,
        passphrase: Blob,
        sobject_prefix: String,
        derivation_data_iv: String,
    ) -> Result<EncryptedPassphrase, String> {
        let transient_key = Self::derive_enc_dec_key(client, sobject_prefix, derivation_data_iv)?;

        // Encrypt passphrase with transient key
        let encrypt_passphrase_req = EncryptRequest {
            key: Some(SobjectDescriptor::TransientKey(transient_key)),
            alg: Algorithm::Aes,
            plain: passphrase,
            mode: Some(CryptMode::Symmetric(CipherMode::Gcm)),
            iv: None,
            ad: None,
            tag_len: Some(Self::GCM_TAG_LEN_BITS),
        };
        let encrypt_passphrase_resp = client
            .encrypt(&encrypt_passphrase_req)
            .map_err(|e| format!("Unable to encrypt : {:?}", e))?;

        // Return data that will be stored in the token
        Ok(EncryptedPassphrase {
            key: encrypt_passphrase_resp.cipher,
            iv: encrypt_passphrase_resp
                .iv
                .ok_or_else(|| format!("Unable to find IV from encrypt response"))?,
            tag: encrypt_passphrase_resp
                .tag
                .ok_or_else(|| format!("Unable to find tag from encrypt response"))?,
        })
    }

    fn decrypt_passphrase(
        client: &SdkmsClient,
        wrapped_key: EncryptedPassphrase,
        sobject_prefix: String,
        derivation_data_iv: String,
    ) -> Result<Blob, String> {
        let transient_key = Self::derive_enc_dec_key(client, sobject_prefix, derivation_data_iv)?;
        // Decrypt passphrase with transient key
        let decrypt_passphrase_req = DecryptRequest {
            key: Some(SobjectDescriptor::TransientKey(transient_key)),
            alg: Some(Algorithm::Aes),
            cipher: wrapped_key.key,
            mode: Some(CryptMode::Symmetric(CipherMode::Gcm)),
            iv: Some(wrapped_key.iv),
            ad: None,
            tag: Some(wrapped_key.tag),
        };
        let decrypt_passphrase_resp = client
            .decrypt(&decrypt_passphrase_req)
            .map_err(|e| format!("Unable to decrypt : {:?}", e))?;
        // Return unwrapped passphrase
        Ok(decrypt_passphrase_resp.plain)
    }

    pub fn new(
        conn_info: ClientConnectionInfo<'_>,
        sobject_prefix: String,
        derivation_data_iv: String,
    ) -> Result<DsmFsOps, String> {
        let cli = Self::create_client(conn_info)?;
        let client = Arc::new(Mutex::new(cli));
        Ok(DsmFsOps {
            client,
            sobject_prefix,
            derivation_data_iv,
        })
    }
}

pub trait DsmInterface {
    const GCM_TAG_LEN_BITS: usize = 128;
    const SOBJECT_LIST_LIMIT: usize = 10;
    const TLS_MIN_VERSION: Version = Version::Tls1_2;

    const DERIVED_KEY_SIZE: u32 = 256;
    const DERIVATION_DATA_PASSPHRASE: &str = "nt-storage-key00";
    const DERIVATION_DATA_HEADER_HMAC: &str = "nt-storage-key01";

    fn dsm_mac_verify_header(&self, header: Blob, mac: Blob) -> impl std::future::Future<Output = Result<(), String>> + Send;
    fn dsm_mac_header(&self, header: Blob) -> impl std::future::Future<Output = Result<Blob, String>> + Send;
    fn dsm_encrypt_passphrase(
        &self,
        passphrase: Blob,
    ) -> impl std::future::Future<Output = Result<EncryptedPassphrase, String>> + Send;
    fn dsm_decrypt_passphrase(
        &self,
        wrapped_key: EncryptedPassphrase,
    ) -> impl std::future::Future<Output = Result<Blob, String>> + Send;
    fn dsm_get_endpoint(&self) -> Result<String, String>;

    fn filter_key_by_prefix(key_list: Vec<Sobject>, prefix: &str) -> Vec<Sobject> {
        key_list
            .into_iter()
            .filter(|s| s.name.as_ref().map(|n| n.starts_with(prefix)).unwrap_or(false))
            .collect()
    }
}

impl DsmInterface for DsmFsOps {
    fn dsm_get_endpoint(&self) -> Result<String, String> {
        let dsm_cli = self
            .client
            .lock()
            .map_err(|e| format!("Unable to lock on DSM client for obtaining endpoint : {:?}", e))?;
        Ok(dsm_cli.api_endpoint().to_string())
    }

    async fn dsm_mac_verify_header(&self, header: Blob, mac: Blob) -> Result<(), String> {
        let self_clone = self.clone();
        let mac_clone = mac.clone();
        let header_clone = header.clone();
        let dsm_mac_task_res = tokio::task::spawn_blocking(move || {
            let dsm_cli = self_clone
                .client
                .lock()
                .map_err(|e| format!("Unable to lock on DSM client for MAC verify operation : {:?}", e))?;
            DsmFsOps::mac_verify_header(
                &dsm_cli,
                header_clone,
                mac_clone,
                self_clone.sobject_prefix,
                self_clone.derivation_data_iv,
            )
        })
        .await
        .map_err(|e| format!("Unable to run task to verify hmac header : {:?}", e))?;
        dsm_mac_task_res
    }

    async fn dsm_mac_header(&self, header: Blob) -> Result<Blob, String> {
        let self_clone = self.clone();
        let header_clone = header.clone();
        let dsm_mac_task_res = tokio::task::spawn_blocking(move || {
            let dsm_cli = self_clone
                .client
                .lock()
                .map_err(|e| format!("Unable to lock on DSM client for MAC operation : {:?}", e))?;
            DsmFsOps::mac_header(
                &dsm_cli,
                header_clone,
                self_clone.sobject_prefix,
                self_clone.derivation_data_iv,
            )
        })
        .await
        .map_err(|e| format!("Unable to run task to hmac header : {:?}", e))?;
        dsm_mac_task_res
    }

    async fn dsm_encrypt_passphrase(&self, passphrase: Blob) -> Result<EncryptedPassphrase, String> {
        let self_clone = self.clone();
        let passphrase_clone = passphrase.clone();
        let dsm_enc_task_res = tokio::task::spawn_blocking(move || {
            let dsm_cli = self_clone
                .client
                .lock()
                .map_err(|e| format!("Unable to lock on DSM client for enc operation : {:?}", e))?;
            DsmFsOps::encrypt_passphrase(
                &dsm_cli,
                passphrase_clone,
                self_clone.sobject_prefix,
                self_clone.derivation_data_iv,
            )
        })
        .await
        .map_err(|e| format!("Unable to run task to enc passphrase : {:?}", e))?;
        dsm_enc_task_res
    }

    async fn dsm_decrypt_passphrase(&self, wrapped_key: EncryptedPassphrase) -> Result<Blob, String> {
        let self_clone = self.clone();
        let wrapped_key_clone = wrapped_key.clone();
        let dsm_dec_task_res = tokio::task::spawn_blocking(move || {
            let dsm_cli = self_clone
                .client
                .lock()
                .map_err(|e| format!("Unable to lock on DSM client for dec operation : {:?}", e))?;
            DsmFsOps::decrypt_passphrase(
                &dsm_cli,
                wrapped_key_clone,
                self_clone.sobject_prefix,
                self_clone.derivation_data_iv,
            )
        })
        .await
        .map_err(|e| format!("Unable to run task to enc passphrase : {:?}", e))?;
        dsm_dec_task_res
    }
}

#[cfg(test)]
mod tests {

    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use std::{env, println as info};

    use lazy_static::lazy_static;
    use mbedtls::pk::Pk;
    use sdkms::api_model::Blob;

    use crate::dsm_key_config::{
        ClientCertificate, ClientConnectionInfo, DsmFsOps, DsmInterface, DEFAULT_DSM_APPS_ENDPOINT, DEFAULT_DSM_ENDPOINT,
    };

    const PLAINTEXT: &str = "hello world. This is a test string.";
    const DSM_APP_ID: &str = "aec67835-04f8-4016-9daa-c524dc315f88";
    const SALM_FS_SECURITY_OBJECT_PREFIX: &str = "fortanix-overlayfs-security-object-build-";
    const COGNAC_FS_SECURITY_OBJECT_PREFIX: &str = "Sample-DataEncryption-Key";
    const DERIVATION_DATA_IV: &str = "sample-persisten";

    lazy_static! {
        static ref DSM_API_KEY: String =
            env::var("FORTANIX_API_KEY").expect("The environment variable FORTANIX_API_KEY must be set for this unit test");
        static ref DSM_TEST_API_KEY: String = env::var("OVERLAYFS_UNIT_TEST_API_KEY")
            .expect("The environment variable OVERLAYFS_UNIT_TEST_API_KEY must be set for this unit test");
    }

    #[test]
    fn test_connection_to_dsm() {
        let conn_info = ClientConnectionInfo {
            fs_api_key: Some(DSM_API_KEY.to_string()),
            auth_cert: None,
            dsm_url: DEFAULT_DSM_ENDPOINT.to_string(),
        };
        let dsm_fs = DsmFsOps::new(
            conn_info,
            SALM_FS_SECURITY_OBJECT_PREFIX.to_string(),
            DERIVATION_DATA_IV.to_string(),
        )
        .unwrap();
        let version = dsm_fs
            .client
            .lock()
            .expect("Client creation failed")
            .version()
            .expect("Unable to get response")
            .api_version;
        let is_version_empty = version.is_empty();

        info!("SDKMS api version is {:?}", version);
        assert!(!is_version_empty);
    }

    #[tokio::test]
    async fn test_connection_to_dsm_with_appcert() {
        // First set of key-cert is typically used by salmiac - app ID is embedded in the app cert
        // Second set of key-cert is used by cognac - app ID may not be embedded in app cert and may be provided as env var
        let key_cert_paths = [
            ("salmiac-overlayfs-ca-signed.key", "salmiac-overlayfs-ca-signed-cert.pem"),
            ("client.key", "client.cert"),
        ];
        let mut sobject_prefix = SALM_FS_SECURITY_OBJECT_PREFIX;
        for (key_path, cert_path) in key_cert_paths {
            let mut test_resource = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            test_resource.push("resources/test");

            if key_path == "client.key" {
                env::set_var("DSM_APP_ID", DSM_APP_ID.to_string());
                sobject_prefix = COGNAC_FS_SECURITY_OBJECT_PREFIX;
            }

            let mut keypath = PathBuf::from(test_resource.clone());
            keypath.push(key_path);
            let mut key_contents: Vec<u8> = Vec::new();
            let _key_size = File::open(keypath).unwrap().read_to_end(&mut key_contents).unwrap();
            key_contents.push(0);

            let mut certpath = PathBuf::from(test_resource);
            certpath.push(cert_path);
            let mut cert_contents: Vec<u8> = Vec::new();
            let _cert_size = File::open(certpath).unwrap().read_to_end(&mut cert_contents).unwrap();

            let mut key = Pk::from_private_key(key_contents.as_slice(), None).unwrap();
            let mut cert_res = ClientCertificate {
                certificate: String::from_utf8(cert_contents).unwrap(),
                key: key.write_private_der_vec().unwrap(),
            };

            // Note - Do not pass api key here otherwise the API key will be used for auth to DSM
            // rather than use the appcert
            let conn_info_enc = ClientConnectionInfo {
                fs_api_key: None,
                auth_cert: Some(&mut cert_res),
                dsm_url: DEFAULT_DSM_APPS_ENDPOINT.to_string(),
            };
            let dsm_fs_enc = DsmFsOps::new(conn_info_enc, sobject_prefix.to_string(), DERIVATION_DATA_IV.to_string()).unwrap();
            let resp = dsm_fs_enc.dsm_encrypt_passphrase(Blob::from(PLAINTEXT)).await.unwrap();

            let conn_info_dec = ClientConnectionInfo {
                fs_api_key: None,
                auth_cert: Some(&mut cert_res),
                dsm_url: DEFAULT_DSM_APPS_ENDPOINT.to_string(),
            };
            let dsm_fs_dec = DsmFsOps::new(conn_info_dec, sobject_prefix.to_string(), DERIVATION_DATA_IV.to_string()).unwrap();
            let dec_resp = dsm_fs_dec.dsm_decrypt_passphrase(resp).await.unwrap();
            assert_eq!(Blob::from(PLAINTEXT), dec_resp);
        }
    }

    #[tokio::test]
    async fn test_dsm_enc_dec_passphrase() {
        let conn_info_enc = ClientConnectionInfo {
            fs_api_key: Some(DSM_API_KEY.to_string()),
            auth_cert: None,
            dsm_url: DEFAULT_DSM_ENDPOINT.to_string(),
        };
        let dsm_fs_enc = DsmFsOps::new(
            conn_info_enc,
            SALM_FS_SECURITY_OBJECT_PREFIX.to_string(),
            DERIVATION_DATA_IV.to_string(),
        )
        .unwrap();
        let wrapped_passhrase = dsm_fs_enc.dsm_encrypt_passphrase(Blob::from(PLAINTEXT)).await.unwrap();

        let conn_info_dec = ClientConnectionInfo {
            fs_api_key: Some(DSM_API_KEY.to_string()),
            auth_cert: None,
            dsm_url: DEFAULT_DSM_ENDPOINT.to_string(),
        };
        let dsm_fs_dec = DsmFsOps::new(
            conn_info_dec,
            SALM_FS_SECURITY_OBJECT_PREFIX.to_string(),
            DERIVATION_DATA_IV.to_string(),
        )
        .unwrap();
        let unwrapped_passphrase = dsm_fs_dec.dsm_decrypt_passphrase(wrapped_passhrase).await.unwrap();

        assert_eq!(Blob::from(PLAINTEXT), unwrapped_passphrase);
    }

    #[tokio::test]
    async fn test_dsm_mac_macverify_verify() {
        let conn_info_mac = ClientConnectionInfo {
            fs_api_key: Some(DSM_API_KEY.to_string()),
            auth_cert: None,
            dsm_url: DEFAULT_DSM_ENDPOINT.to_string(),
        };
        let dsm_fs_mac = DsmFsOps::new(
            conn_info_mac,
            SALM_FS_SECURITY_OBJECT_PREFIX.to_string(),
            DERIVATION_DATA_IV.to_string(),
        )
        .unwrap();
        let mac = dsm_fs_mac.dsm_mac_header(Blob::from(PLAINTEXT)).await.unwrap();

        let conn_info_macv = ClientConnectionInfo {
            fs_api_key: Some(DSM_API_KEY.to_string()),
            auth_cert: None,
            dsm_url: DEFAULT_DSM_ENDPOINT.to_string(),
        };
        let dsm_fs_macv = DsmFsOps::new(
            conn_info_macv,
            SALM_FS_SECURITY_OBJECT_PREFIX.to_string(),
            DERIVATION_DATA_IV.to_string(),
        )
        .unwrap();
        dsm_fs_macv.dsm_mac_verify_header(Blob::from(PLAINTEXT), mac).await.unwrap();
    }

    #[test]
    fn test_multiple_overlayfs_keys() {
        let conn_info = ClientConnectionInfo {
            fs_api_key: Some(DSM_TEST_API_KEY.to_string()),
            auth_cert: None,
            dsm_url: DEFAULT_DSM_ENDPOINT.to_string(),
        };
        let client = DsmFsOps::create_client(conn_info).unwrap();
        match DsmFsOps::get_key_by_prefix(&client, SALM_FS_SECURITY_OBJECT_PREFIX) {
            Ok(_) => {
                assert!(false);
            }
            Err(err) => {
                assert_eq!(
                    err,
                    format!(
                        "Unexpected behaviour - found 2 keys with prefix {:?}",
                        SALM_FS_SECURITY_OBJECT_PREFIX
                    )
                );
            }
        }
    }
}
