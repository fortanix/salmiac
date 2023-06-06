use std::borrow::Borrow;
use std::string::ToString;
use log::info;
use sdkms::api_model::{
    Algorithm, Blob, CipherMode, CryptMode, DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse,
    ListSobjectsParams, Sobject, SobjectDescriptor,
};
use sdkms::SdkmsClient;

use crate::certificate::CertificateWithPath;
use crate::file_system::find_env_or_err;

const GCM_TAG_LEN_BITS: usize = 128;
const SOBJECT_LIST_LIMIT: usize = 10;
pub const DEFAULT_DSM_ENDPOINT: &str = "https://amer.smartkey.io/";
const OVERLAY_FS_SECURITY_OBJECT_PREFIX: &str = "fortanix-overlayfs-security-object-build-";

struct ClientWithKey {
    overlayfs_key: Sobject,
    dsm_client: SdkmsClient,
}

fn dsm_create_client(env_vars: &[(String, String)], _auth_cert: Option<&CertificateWithPath>) -> Result<SdkmsClient, String> {
    info!("Looking for env variables needed to create DSM client.");
    let endpoint = find_env_or_err("FS_DSM_ENDPOINT", env_vars).unwrap_or(DEFAULT_DSM_ENDPOINT.to_string());
    let api_key = find_env_or_err("FS_API_KEY", env_vars)?;

    info!("Attemping to create DSM client with endpoint {:?}", endpoint);
    // Note - mapping an empty error here, mapping an error type results in a hang
    // Needs to be investigated.
    let client = sdkms::SdkmsClient::builder()
        .with_api_endpoint(&endpoint)
        .build()
        .map_err(|_| format!("DSM client build failed"))?
        .authenticate_with_api_key(&*api_key)
        .map_err(|_| format!("Unable to auth with api key"))?;

    Ok(client)
}

fn dsm_get_keys(client: &SdkmsClient, query_params: Option<&ListSobjectsParams>) -> Result<Vec<Sobject>, String> {
    client
        .list_sobjects(query_params)
        .map_err(|_| format!("Unable to list sobjects"))
}

fn dsm_filter_key_by_prefix(key_list: Vec<Sobject>, prefix: &str) -> Vec<Sobject> {
    key_list.into_iter().filter(|s| {
        s.name.as_ref().map(|n| n.starts_with(prefix)).unwrap_or_default()
    }).collect()
}

fn dsm_get_key_by_prefix(client: &SdkmsClient, prefix: &str) -> Result<Sobject, String> {
    let mut res_key_list_len = 1;
    let mut offset = 0;
    let mut prefixed_key;
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

            prefixed_key = dsm_filter_key_by_prefix(key_list, prefix);
            if prefixed_key.len() > 0 {
                result_key.append(&mut prefixed_key);
            }
        }
    if result_key.is_empty() {
        Err(format!("Unable to find key with prefix {:?}", prefix))
    } else if result_key.len() > 1 {
        Err(format!("Unexpected behaviour - found {:?} keys with prefix {:?}", result_key.len(), prefix))
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

fn dsm_get_overlayfs_key(cert_list: &Vec<CertificateWithPath>, env_vars: &[(String, String)]) -> Result<ClientWithKey, String> {
    let auth_cert = cert_list.get(0).map(|fst| fst.borrow());
    let client = dsm_create_client(env_vars, auth_cert)?;
    let overlay_fs_key = dsm_get_key_by_prefix(&client, OVERLAY_FS_SECURITY_OBJECT_PREFIX)?;
    Ok(ClientWithKey {
        overlayfs_key: overlay_fs_key,
        dsm_client: client,
    })
}

pub(crate) fn dsm_enc_with_overlayfs_key(
    cert_list: &Vec<CertificateWithPath>,
    env_vars: &[(String, String)],
    plaintext: Blob,
) -> Result<EncryptResponse, String> {
    let client_key_pair = dsm_get_overlayfs_key(cert_list, env_vars)?;
    let enc_req = dsm_generate_enc_req(&client_key_pair.overlayfs_key, plaintext)?;
    dsm_encrypt_blob(&enc_req, &client_key_pair.dsm_client)
}

pub(crate) fn dsm_dec_with_overlayfs_key(
    cert_list: &Vec<CertificateWithPath>,
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

    use std::{env, println as info};
    use lazy_static::lazy_static;
    use sdkms::api_model::Blob;
    use crate::dsm_key_config::{dsm_create_client, dsm_dec_with_overlayfs_key, dsm_enc_with_overlayfs_key, dsm_get_overlayfs_key};

    const PLAINTEXT: &str = "hello world. This is a test string.";
    const DSM_ENDPOINT: &str = "https://amer.smartkey.io/";

    lazy_static! {
        static ref DSM_API_KEY: String =
            env::var("FORTANIX_API_KEY")
            .expect("The environment variable FORTANIX_API_KEY must be set for this unit test");
        static ref DSM_TEST_API_KEY: String =
            env::var("OVERLAYFS_UNIT_TEST_API_KEY")
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
    fn test_enc_dec_blob() {
        let enc_resp = dsm_enc_with_overlayfs_key(&vec![], &DSM_ENV_VARS, Blob::from(PLAINTEXT)).unwrap();

        let dec_resp = dsm_dec_with_overlayfs_key(
            &vec![],
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
        match dsm_get_overlayfs_key(&vec![], &DSM_ERR_ENV_VARS) {
            Ok(_) => {
                assert!(false);
            }
            Err(err) => {
                assert_eq!(err, "Unexpected behaviour - found 2 keys with prefix \"fortanix-overlayfs-security-object-build-\"");
            }
        }
    }
}
