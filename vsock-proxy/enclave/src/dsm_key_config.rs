use std::ffi::CString;
use std::string::ToString;
use std::sync::Arc;

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
    Algorithm, Blob, CipherMode, CryptMode, DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse,
    ListSobjectsParams, Sobject, SobjectDescriptor,
};
use sdkms::SdkmsClient;
use url;

use crate::certificate::{CertificateResult};
use crate::file_system::find_env_or_err;

const GCM_TAG_LEN_BITS: usize = 128;
const SOBJECT_LIST_LIMIT: usize = 10;
pub const DEFAULT_DSM_ENDPOINT: &str = "https://amer.smartkey.io/";
const OVERLAY_FS_SECURITY_OBJECT_PREFIX: &str = "fortanix-overlayfs-security-object-build-";
pub const DEFAULT_DSM_APP_ENDPOINT: &str = "https://apps.amer.smartkey.io/";
const TLS_MIN_VERSION: Version = Version::Tls1_2;

struct ClientWithKey {
    overlayfs_key: Sobject,
    dsm_client: SdkmsClient,
}

fn dsm_create_client(
    env_vars: &[(String, String)],
    auth_cert: Option<&mut CertificateResult>,
) -> Result<SdkmsClient, String> {
    info!("Looking for env variables needed to create DSM client.");
    let api_key = find_env_or_err("FS_API_KEY", env_vars).unwrap_or("".to_string());

    if api_key.is_empty() {
        info!("Using app cert for auth with DSM");
        let endpoint = find_env_or_err("FS_DSM_ENDPOINT", env_vars).unwrap_or(DEFAULT_DSM_APP_ENDPOINT.to_string());
        let endoint_url = url::Url::parse(&*endpoint).map_err(|e| format!("Unable to parse endpoint : {:?}", e))?;
        let host = endoint_url
            .host_str()
            .ok_or_else(|| format!("Unable to get host from endpoint"))?;
        let hyper_client = dsm_create_hyper_client_with_cert(
            host.to_string(),
            auth_cert.ok_or_else(|| format!("Unable to get auth cert for connection to DSM"))?,
        )?;

        Ok(SdkmsClient::builder()
            .with_hyper_client(hyper_client)
            .with_api_endpoint(&*endpoint)
            .build()
            .map_err(|_| format!("DSM client build failed"))?
            .authenticate_with_cert(None)
            .map_err(|_| format!("Unable to auth with app cert"))?)
    } else {
        info!("Using API key for auth with DSM");
        let endpoint = find_env_or_err("FS_DSM_ENDPOINT", env_vars).unwrap_or(DEFAULT_DSM_ENDPOINT.to_string());
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

fn dsm_create_hyper_client_with_cert(host: String, auth_cert: &mut CertificateResult) -> Result<Arc<Client>, String> {
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_authmode(AuthMode::Optional);
    config.set_rng(Arc::new(mbedtls::rng::Rdrand));
    config
        .set_min_version(TLS_MIN_VERSION)
        .map_err(|e| format!("TLS configuration failed: {:?}", e))?;

    let cert = {
        let cert_pem = CString::new(&*auth_cert.certificate)
            .map_err(|e| format!("Can't create cstring from cert pem {:?}", e.to_string()))?;
        let app_cert = Certificate::from_pem_multiple(cert_pem.as_bytes_with_nul())
            .map_err(|e| format!("Parsing certificate failed: {:?}", e))?;

        Arc::new(app_cert)
    };

    let der_key = auth_cert.key.write_private_der_vec()
        .map_err(|e| format!("Failed writing certificate key as der format. {:?}", e))?;
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

fn dsm_get_keys(client: &SdkmsClient, query_params: Option<&ListSobjectsParams>) -> Result<Vec<Sobject>, String> {
    client
        .list_sobjects(query_params)
        .map_err(|_| format!("Unable to list sobjects"))
}

fn dsm_filter_key_by_prefix(key_list: Vec<Sobject>, prefix: &str) -> Vec<Sobject> {
    key_list
        .into_iter()
        .filter(|s| s.name.as_ref().map(|n| n.starts_with(prefix)).unwrap_or(false))
        .collect()
}

fn dsm_get_key_by_prefix(client: &SdkmsClient, prefix: &str) -> Result<Sobject, String> {
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
            limit: Some(SOBJECT_LIST_LIMIT),
            offset: Some(offset),
            sort: Default::default(),
        };
        let key_list = dsm_get_keys(client, Some(&query_params))?;
        res_key_list_len = key_list.len();
        offset = offset + res_key_list_len;

        let mut prefixed_key = dsm_filter_key_by_prefix(key_list, prefix);
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

fn dsm_generate_enc_req(key: &Sobject, plaintext: Blob) -> Result<EncryptRequest, String> {
    let kid = key
        .kid
        .ok_or_else(|| format!("Unable to find kid in overlay FS key object for encryption"))?;

    Ok(EncryptRequest {
        key: Some(SobjectDescriptor::Kid(kid)),
        alg: Algorithm::Aes,
        plain: plaintext,
        mode: Some(CryptMode::Symmetric(CipherMode::Gcm)),
        iv: None,
        ad: None,
        tag_len: Some(GCM_TAG_LEN_BITS),
    })
}

fn dsm_encrypt_blob(enc_req: &EncryptRequest, client: &SdkmsClient) -> Result<EncryptResponse, String> {
    client
        .encrypt(&enc_req)
        .map_err(|_| format!("Unable to encrypt using DSM client"))
}

fn dsm_generate_dec_req(key: &Sobject, ciphertext: Blob, iv: Blob, tag: Blob) -> Result<DecryptRequest, String> {
    let kid = key
        .kid
        .ok_or_else(|| format!("Unable to find kid in overlay FS key object for decryption"))?;

    Ok(DecryptRequest {
        key: Some(SobjectDescriptor::Kid(kid)),
        alg: Some(Algorithm::Aes),
        cipher: ciphertext,
        mode: Some(CryptMode::Symmetric(CipherMode::Gcm)),
        iv: Some(iv),
        ad: None,
        tag: Some(tag),
    })
}

fn dsm_decrypt_blob(dec_req: &DecryptRequest, client: &SdkmsClient) -> Result<DecryptResponse, String> {
    client
        .decrypt(&dec_req)
        .map_err(|_| format!("Unable to decrypt using DSM client"))
}

fn dsm_get_overlayfs_key(
    cert_list: Option<&mut CertificateResult>,
    env_vars: &[(String, String)],
) -> Result<ClientWithKey, String> {
    let client = dsm_create_client(env_vars, cert_list)?;
    let overlay_fs_key = dsm_get_key_by_prefix(&client, OVERLAY_FS_SECURITY_OBJECT_PREFIX)?;
    Ok(ClientWithKey {
        overlayfs_key: overlay_fs_key,
        dsm_client: client,
    })
}

pub(crate) fn dsm_enc_with_overlayfs_key(
    cert_list: Option<&mut CertificateResult>,
    env_vars: &[(String, String)],
    plaintext: Blob,
) -> Result<EncryptResponse, String> {
    let client_key_pair = dsm_get_overlayfs_key(cert_list, env_vars)?;
    let enc_req = dsm_generate_enc_req(&client_key_pair.overlayfs_key, plaintext)?;
    dsm_encrypt_blob(&enc_req, &client_key_pair.dsm_client)
}

pub(crate) fn dsm_dec_with_overlayfs_key(
    cert_list: Option<&mut CertificateResult>,
    env_vars: &[(String, String)],
    ciphertext: Blob,
    iv: Blob,
    tag: Blob,
) -> Result<DecryptResponse, String> {
    let client_key_pair = dsm_get_overlayfs_key(cert_list, env_vars)?;
    let dec_req = dsm_generate_dec_req(&client_key_pair.overlayfs_key, ciphertext, iv, tag)?;
    dsm_decrypt_blob(&dec_req, &client_key_pair.dsm_client)
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

    use crate::certificate::{CertificateResult};
    use crate::dsm_key_config::{
        dsm_create_client, dsm_dec_with_overlayfs_key, dsm_enc_with_overlayfs_key, dsm_get_overlayfs_key,
        OVERLAY_FS_SECURITY_OBJECT_PREFIX,
    };

    const PLAINTEXT: &str = "hello world. This is a test string.";
    const DSM_ENDPOINT: &str = "https://amer.smartkey.io/";

    lazy_static! {
        static ref DSM_API_KEY: String =
            env::var("FORTANIX_API_KEY").expect("The environment variable FORTANIX_API_KEY must be set for this unit test");
        static ref DSM_TEST_API_KEY: String = env::var("OVERLAYFS_UNIT_TEST_API_KEY")
            .expect("The environment variable OVERLAYFS_UNIT_TEST_API_KEY must be set for this unit test");
        static ref DSM_ENV_VARS: Vec<(String, String)> = vec![
            ("FS_DSM_ENDPOINT".to_string(), DSM_ENDPOINT.to_string()),
            ("FS_API_KEY".to_string(), DSM_API_KEY.to_string()),
        ];
        static ref DSM_ERR_ENV_VARS: Vec<(String, String)> = vec![
            ("FS_DSM_ENDPOINT".to_string(), DSM_ENDPOINT.to_string()),
            ("FS_API_KEY".to_string(), DSM_TEST_API_KEY.to_string()),
        ];
    }

    #[test]
    fn test_connection_to_dsm() {
        let dsm_client = dsm_create_client(&DSM_ENV_VARS, None);
        let version = dsm_client
            .expect("Client creation failed")
            .version()
            .expect("Unable to get response")
            .api_version;
        let is_version_empty = version.is_empty();

        info!("SDKMS api version is {:?}", version);
        assert!(!is_version_empty);
    }

    #[test]
    fn test_connection_to_dsm_with_appcert() {
        let mut test_resource = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_resource.push("resources/test");

        let mut keypath = PathBuf::from(test_resource.clone());
        keypath.push("salmiac-overlayfs-ca-signed.key");
        let mut key_contents: Vec<u8> = Vec::new();
        let _key_size = File::open(keypath).unwrap().read_to_end(&mut key_contents).unwrap();
        key_contents.push(0);

        let mut certpath = PathBuf::from(test_resource);
        certpath.push("salmiac-overlayfs-ca-signed-cert.pem");
        let mut cert_contents: Vec<u8> = Vec::new();
        let _cert_size = File::open(certpath).unwrap().read_to_end(&mut cert_contents).unwrap();

        let key = Pk::from_private_key(key_contents.as_slice(), None).unwrap();
        let mut cert_res = CertificateResult {
            certificate: String::from_utf8(cert_contents).unwrap(),
            key,
        };

        // Note - Do not pass DSM_ENV_VARS here otherwise the API key will be used for auth to DSM
        // rather than use the appcert
        let enc_resp = dsm_enc_with_overlayfs_key(Some(&mut cert_res), &vec![], Blob::from(PLAINTEXT)).unwrap();

        let dec_resp = dsm_dec_with_overlayfs_key(
            Some(&mut cert_res),
            &vec![],
            enc_resp.cipher,
            enc_resp.iv.unwrap(),
            enc_resp.tag.unwrap(),
        )
        .unwrap();
        assert_eq!(Blob::from(PLAINTEXT), dec_resp.plain);
    }

    #[test]
    fn test_enc_dec_blob() {
        let enc_resp = dsm_enc_with_overlayfs_key(None, &DSM_ENV_VARS, Blob::from(PLAINTEXT)).unwrap();

        let dec_resp = dsm_dec_with_overlayfs_key(
            None,
            &DSM_ENV_VARS,
            enc_resp.cipher,
            enc_resp.iv.unwrap(),
            enc_resp.tag.unwrap(),
        )
        .unwrap();
        assert_eq!(Blob::from(PLAINTEXT), dec_resp.plain);
    }

    #[test]
    fn test_multiple_overlayfs_keys() {
        match dsm_get_overlayfs_key(None, &DSM_ERR_ENV_VARS) {
            Ok(_) => {
                assert!(false);
            }
            Err(err) => {
                assert_eq!(
                    err,
                    format!(
                        "Unexpected behaviour - found 2 keys with prefix {:?}",
                        OVERLAY_FS_SECURITY_OBJECT_PREFIX
                    )
                );
            }
        }
    }
}
