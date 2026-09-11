use std::env;
use std::net::IpAddr;

use log::{info, warn};
use shared::extract_enum_value;
use shared::models::{CertificateErrorCode, NBDConfiguration, NBDExport, SetupMessages};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task;
use tokio::time::Duration;

pub const NBD_EXPORTS: &'static [NBDExportConfig] = &[
    NBDExportConfig {
        name: "enclave-fs",
        block_file_path: "/opt/fortanix/enclave-os/Blockfile.ext4",
        port: 7777,
        is_read_only: true,
    },
    NBDExportConfig {
        name: "enclave-rw-fs",
        block_file_path: "/opt/fortanix/enclave-os/overlayfs/Blockfile-rw.ext4",
        port: 7778,
        is_read_only: false,
    },
];

const CSR_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub struct NBDExportConfig {
    pub name: &'static str,

    pub block_file_path: &'static str,

    pub port: u16,

    pub is_read_only: bool,
}

pub fn node_agent_address() -> Option<String> {
    env::vars().find_map(|(k, v)| {
        if k == "NODE_AGENT" {
            if !v.starts_with("http://") {
                Some("http://".to_string() + &v)
            } else {
                Some(v)
            }
        } else {
            None
        }
    })
}

pub async fn handle_csr_message<
    Socket: AsyncWrite + AsyncRead + Unpin + Send,
    CertApi: CertificateApi + Send + 'static,
>(
    vsock: &mut Socket,
    cert_api: CertApi,
    csr: String,
) -> Result<(), String> {
    handle_certificate_request(
        vsock,
        cert_api,
        csr,
        node_agent_address(),
        CSR_REQUEST_TIMEOUT,
    )
    .await
}

async fn handle_certificate_request<
    Socket: AsyncWrite + AsyncRead + Unpin + Send,
    CertApi: CertificateApi + Send + 'static,
>(
    vsock: &mut Socket,
    cert_api: CertApi,
    csr: String,
    address: Option<String>,
    timeout: Duration,
) -> Result<(), String> {
    let result = match address {
        None => Err(CertificateErrorCode::Unavailable),
        Some(address) => {
            info!("Requesting CCM for App Certificate, timing out after 60 sec...");
            match tokio::time::timeout(
                timeout,
                task::spawn_blocking(move || cert_api.request_issue_certificate(&address, csr)),
            )
            .await
            {
                Ok(Ok(Ok(cert))) => Ok(cert),
                Ok(Ok(Err(err))) => {
                    // Print the error here as caller won't have this information
                    warn!("Certificate request failed: {}", err);
                    Err(CertificateErrorCode::RequestFailed)
                }
                Ok(Err(err)) => {
                    // Print the error here as caller won't have this information
                    warn!("Certificate failed with internal error: {}", err);
                    Err(CertificateErrorCode::InternalError)
                }
                Err(_) => Err(CertificateErrorCode::Timeout),
            }
        }
    };

    match result {
        Ok(cert) => {
            info!("Received cert message, sending to enclave");
            vsock.write_lv(&SetupMessages::Certificate(cert)).await
        }
        Err(code) => {
            // Always reply, including when NODE_AGENT is absent, so the enclave cannot
            // remain blocked waiting for a certificate response and can retry after some time.
            vsock
                .write_lv(&SetupMessages::CertificateError(code))
                .await?;
            info!("Error requesting App Certificate: {:?}", code);
            Err(format!("{:?}", code))
        }
    }
}

pub async fn communicate_certificates<
    Socket: AsyncWrite + AsyncRead + Unpin + Send,
    CertApi: CertificateApi + Sync + Send + Clone + 'static,
>(
    vsock: &mut Socket,
    cert_api: CertApi,
) -> Result<(), String> {
    // Process certificate requests. There can be any number
    // of certificate requests, including 0.
    loop {
        let cert_api = cert_api.clone();

        let msg: SetupMessages = vsock.read_lv().await?;

        match msg {
            SetupMessages::NoMoreCertificates => return Ok(()),
            SetupMessages::CSR(csr) => handle_csr_message(vsock, cert_api, csr).await?,
            other => {
                return Err(format!(
                    "While processing certificate requests, expected \
                           SetupMessages::CSR(csr) or SetupMessages::NoMoreCertificates, \
                           but got {:?}",
                    other
                ))
            }
        };
    }
}

pub trait CertificateApi {
    fn request_issue_certificate(&self, url: &str, csr_pem: String) -> Result<String, String>;
}

pub async fn setup_file_system<Socket: AsyncWrite + AsyncRead + Unpin + Send>(
    enclave_port: &mut Socket,
    tap_l3_address: IpAddr,
) -> Result<(), String> {
    send_nbd_configuration(enclave_port, tap_l3_address).await?;

    log_encrypted_space_available(enclave_port).await
}

async fn send_nbd_configuration<Socket: AsyncWrite + AsyncRead + Unpin + Send>(
    enclave_port: &mut Socket,
    tap_l3_address: IpAddr,
) -> Result<(), String> {
    let exports = NBD_EXPORTS
        .iter()
        .map(|e| NBDExport {
            name: e.name.to_string(),
            port: e.port,
        })
        .collect();

    let configuration = NBDConfiguration {
        address: tap_l3_address,
        exports,
    };

    enclave_port
        .write_lv(&SetupMessages::NBDConfiguration(configuration))
        .await
}

async fn log_encrypted_space_available<Socket: AsyncWrite + AsyncRead + Unpin + Send>(
    vsock: &mut Socket,
) -> Result<(), String> {
    let encrypted_space_size = extract_enum_value!(vsock.read_lv().await?, SetupMessages::EncryptedSpaceAvailable(s) => s)?;
    info!("Encrypted space available = {}B", encrypted_space_size);
    Ok(())
}
