/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use api_model::converter::CertificateConfig;
use log::debug;
use mbedtls::pk::Pk;
use mbedtls::rng::Rdrand;
use shared::models::SetupMessages;
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use shared::{extract_enum_value, get_relative_path};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::enclave::write_to_file;

const RSA_SIZE: u32 = 3072;

const RSA_EXPONENT: u32 = 0x10001;

pub struct CertificateResult {
    pub certificate: String,

    pub key: Pk,
}

pub(crate) struct CertificateWithPath {
    pub(crate) certificate_result: CertificateResult,

    key_path: PathBuf,

    certificate_path: PathBuf,
}

impl CertificateWithPath {
    pub(crate) fn new(certificate_result: CertificateResult, cert_config: &CertificateConfig, fs_root: &Path) -> Self {
        // PathBuf.join replaces the path with the second path if its absolute. So always convert
        // the key and cert path to a relative path which is added to the enclave user program's
        // filesystem root
        let key_path = fs_root.join(get_relative_path(cert_config.key_path_or_default()));
        let certificate_path = fs_root.join(get_relative_path(cert_config.cert_path_or_default()));

        CertificateWithPath {
            certificate_result,
            key_path,
            certificate_path,
        }
    }
}

pub(crate) fn write_certificate(cert_with_path: &mut CertificateWithPath) -> Result<(), String> {
    // Get a mutable reference to the private key, mbedtls requires the key to be
    // mutable even though it does not make any changes to it. This is done
    // because the underlying C libraries use a void * reference rather than
    // a const void * reference to the input
    let key = &mut cert_with_path.certificate_result.key;
    let key_as_pem = key
        .write_private_pem_string()
        .map_err(|err| format!("Failed to write key as PEM format. {:?}", err))?;

    debug!(
        "Writing key to file {:?} and cert to file {:?}",
        cert_with_path.key_path, cert_with_path.certificate_path
    );
    write_to_file(&cert_with_path.key_path, &key_as_pem, "key")?;
    write_to_file(
        &cert_with_path.certificate_path,
        &cert_with_path.certificate_result.certificate,
        "certificate",
    )
}

pub(crate) async fn request_certificate<Socket: AsyncWrite + AsyncRead + Unpin + Send>(
    vsock: &mut Socket,
    csr: String,
) -> Result<String, String> {
    vsock.write_lv(&SetupMessages::CSR(csr)).await?;

    extract_enum_value!(vsock.read_lv().await?, SetupMessages::Certificate(s) => s)
}

pub(crate) fn create_signer_key() -> Result<Pk, String> {
    let mut rng = Rdrand;
    Pk::generate_rsa(&mut rng, RSA_SIZE, RSA_EXPONENT).map_err(|err| format!("Failed to generate RSA key. {:?}", err))
}

pub(crate) trait CSRApi {
    fn get_remote_attestation_csr(
        &self,
        cert_config: &CertificateConfig,
        app_config_id: &Option<String>,
        key: &mut Pk,
    ) -> Result<String, String>;
}

pub(crate) struct EmAppCSRApi {}
impl CSRApi for EmAppCSRApi {
    fn get_remote_attestation_csr(
        &self,
        cert_config: &CertificateConfig,
        app_config_id: &Option<String>,
        key: &mut Pk,
    ) -> Result<String, String> {
        let subject;
        let common_name = cert_config.subject.as_ref().map(|e| e.as_str()).unwrap_or_default();
        if common_name.is_empty() {
            subject = pkix::types::Name::from(vec![]);
        } else {
            subject = em_app::common_name_to_subject(common_name);
        }

        let alt_names = cert_config.alt_names.clone().into_iter().map(|s| Cow::Owned(s)).collect();

        em_app::get_remote_attestation_csr_subject(
            "localhost", //this param is not used for now
            &subject,
            key,
            Some(alt_names),
            app_config_id.as_deref(),
        )
        .map_err(|err| format!("Failed to get CSR. {:?}", err))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use api_model::converter::{CertIssuer, CertificateConfig, KeyType};
    use mbedtls::pk::Pk;
    use parent_lib::{communicate_certificates, CertificateApi};
    use shared::socket::InMemorySocket;
    use tokio::runtime::Runtime;

    use crate::certificate::CSRApi;
    use crate::enclave::setup_enclave_certification;

    struct MockCertApi {}
    impl CertificateApi for MockCertApi {
        fn request_issue_certificate(&self, _url: &str, _csr_pem: String) -> Result<String, String> {
            Ok("certificate".to_string())
        }
    }

    struct MockCSRApi {}
    impl CSRApi for MockCSRApi {
        fn get_remote_attestation_csr(
            &self,
            _cert_config: &CertificateConfig,
            _app_config_id: &Option<String>,
            _key: &mut Pk,
        ) -> Result<String, String> {
            Ok("csr".to_string())
        }
    }

    async fn parent(mut parent_socket: InMemorySocket) -> Result<(), String> {
        std::env::set_var("NODE_AGENT", "test");
        communicate_certificates(&mut parent_socket, MockCertApi {}).await
    }

    async fn enclave(mut enclave_socket: InMemorySocket, mut cert_configs: Vec<CertificateConfig>) -> () {
        let result = setup_enclave_certification(
            &mut enclave_socket,
            MockCSRApi {},
            &None,
            &mut cert_configs,
            Path::new("/"),
            true,
        )
        .await
        .expect("Request certificate OK");

        assert_eq!(result[0].certificate_result.certificate, "certificate")
    }

    async fn enclave_no_certs(mut enclave_socket: InMemorySocket) -> () {
        let result = setup_enclave_certification(&mut enclave_socket, MockCSRApi {}, &None, &mut vec![], Path::new("/"), true)
            .await
            .expect("Request certificate OK");

        assert!(result.is_empty())
    }

    #[test]
    fn setup_enclave_certification_certificate_present_correct_pass() {
        let (enclave_socket, parent_socket) = InMemorySocket::socket_pair();
        let certificate_config = CertificateConfig {
            issuer: CertIssuer::ManagerCa,
            subject: None,
            alt_names: vec![],
            key_type: KeyType::Rsa,
            key_param: None,
            key_path: None,
            cert_path: None,
            chain_path: None,
        };
        let rt = Runtime::new().expect("Tokio runtime OK");

        rt.block_on(async move {
            let a = tokio::spawn(parent(parent_socket));
            let b = tokio::spawn(enclave(enclave_socket, vec![certificate_config]));

            let (a_result, b_result) = tokio::join!(a, b);

            assert!(a_result.is_ok());
            assert!(b_result.is_ok());
        });
    }

    #[test]
    fn setup_enclave_certification_no_certificate_present_correct_pass() {
        let (enclave_socket, parent_socket) = InMemorySocket::socket_pair();
        let rt = Runtime::new().expect("Tokio runtime OK");

        rt.block_on(async move {
            let a = tokio::spawn(parent(parent_socket));
            let b = tokio::spawn(enclave_no_certs(enclave_socket));

            let (a_result, b_result) = tokio::join!(a, b);

            assert!(a_result.is_ok());
            assert!(b_result.is_ok());
        });
    }
}
