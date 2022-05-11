use api_model::CertificateConfig;
use mbedtls::pk::Pk;
use mbedtls::rng::Rdrand;
use tokio_vsock::VsockStream as AsyncVsockStream;

use crate::enclave::write_to_file;
use shared::device::SetupMessages;
use shared::extract_enum_value;
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};

use std::path::Path;

const RSA_SIZE: u32 = 3072;

const RSA_EXPONENT: u32 = 0x10001;

pub struct CertificateResult {
    pub certificate: String,

    pub key: Pk,
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

pub fn write_certificate_info_to_file_system(key: &str, certificate: &str, settings: &CertificateConfig) -> Result<(), String> {
    let key_path = settings.key_path.as_ref().map_or("key", |e| e.as_str());

    let certificate_path = settings.cert_path.as_ref().map_or("cert", |e| e.as_str());

    write_to_file(Path::new(key_path), &key)?;
    write_to_file(Path::new(certificate_path), &certificate)
}
