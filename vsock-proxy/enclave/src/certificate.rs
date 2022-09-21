use api_model::CertificateConfig;
use mbedtls::pk::Pk;
use mbedtls::rng::Rdrand;
use tokio_vsock::VsockStream as AsyncVsockStream;

use shared::extract_enum_value;
use shared::models::SetupMessages;
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use crate::enclave::write_to_file;
use std::path::{Path, PathBuf};

const RSA_SIZE: u32 = 3072;

const RSA_EXPONENT: u32 = 0x10001;

pub struct CertificateResult {
    pub certificate: String,

    pub key: Pk,
}

pub struct CertificateWithPath {
    pub certificate_result: CertificateResult,

    key_path: PathBuf,

    certificate_path: PathBuf
}

impl CertificateWithPath {
    pub fn new(certificate_result: CertificateResult, cert_config: &CertificateConfig, fs_root: &Path) -> Self {
        let key_path = fs_root.join(cert_config.key_path_or_default());
        let certificate_path = fs_root.join(cert_config.cert_path_or_default());

        CertificateWithPath {
            certificate_result,
            key_path,
            certificate_path
        }
    }
}

pub fn write_certificate(cert_with_path: &mut CertificateWithPath) -> Result<(), String> {
    let key_as_pem = cert_with_path
        .certificate_result
        .key
        .write_private_pem_string()
        .map_err(|err| format!("Failed to write key as PEM format. {:?}", err))?;

    write_to_file(&cert_with_path.key_path, &key_as_pem, "key")?;
    write_to_file(&cert_with_path.certificate_path, &cert_with_path.certificate_result.certificate, "certificate")
}

pub async fn request_certificate(
    vsock: &mut AsyncVsockStream,
    cert_settings: &CertificateConfig,
    app_config_id: &Option<String>,
) -> Result<CertificateResult, String> {
    let mut rng = Rdrand;
    let mut key =
        Pk::generate_rsa(&mut rng, RSA_SIZE, RSA_EXPONENT).map_err(|err| format!("Failed to generate RSA key. {:?}", err))?;

    let common_name = cert_settings.subject.as_ref().map(|e| e.as_str()).unwrap_or("localhost");

    let csr = em_app::get_remote_attestation_csr(
        "localhost", //this param is not used for now
        common_name,
        &mut key,
        None,
        app_config_id.as_deref(),
    )
    .map_err(|err| format!("Failed to get CSR. {:?}", err))?;

    vsock.write_lv(&SetupMessages::CSR(csr)).await?;

    let certificate = extract_enum_value!(vsock.read_lv().await?, SetupMessages::Certificate(s) => s)?;

    Ok(CertificateResult { certificate, key })
}
