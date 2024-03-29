use std::env;
use std::net::IpAddr;

use log::info;
use shared::extract_enum_value;
use shared::models::{NBDConfiguration, NBDExport, SetupMessages};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use tokio::io::{AsyncRead, AsyncWrite};

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

pub struct NBDExportConfig {
    pub name: &'static str,

    pub block_file_path: &'static str,

    pub port: u16,

    pub is_read_only: bool,
}

pub async fn communicate_certificates<Socket: AsyncWrite + AsyncRead + Unpin + Send, CertApi: CertificateApi>(
    vsock: &mut Socket,
    cert_api: CertApi,
) -> Result<(), String> {
    // Don't bother looking for a node agent address unless there's at least one
    // certificate configured. This allows us to run with the NODE_AGENT
    // environment variable being unset, if there are no configured certificates.
    let mut node_agent_address: Option<String> = None;

    // Process certificate requests until we get the SetupSuccessful message
    // indicating that the enclave is done with setup. There can be any number
    // of certificate requests, including 0.
    loop {
        let msg: SetupMessages = vsock.read_lv().await?;

        match msg {
            SetupMessages::NoMoreCertificates => return Ok(()),
            SetupMessages::CSR(csr) => {
                let addr = match node_agent_address {
                    Some(ref addr) => addr.clone(),
                    None => {
                        let result = env::var("NODE_AGENT")
                            .map_err(|err| format!("Failed to read NODE_AGENT var. {:?}", err))?;

                        let addr = if !result.starts_with("http://") {
                            "http://".to_string() + &result
                        } else {
                            result
                        };
                        node_agent_address = Some(addr.clone());
                        addr
                    },
                };
                let certificate = cert_api.request_issue_certificate(&addr, csr)?;

                vsock.write_lv(&SetupMessages::Certificate(certificate)).await?;
            },
            other => return Err(format!("While processing certificate requests, expected SetupMessages::CSR(csr) or SetupMessages:SetupSuccessful, but got {:?}",
                                        other)),
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

    enclave_port.write_lv(&SetupMessages::NBDConfiguration(configuration)).await
}

async fn log_encrypted_space_available<Socket: AsyncWrite + AsyncRead + Unpin + Send>(
    vsock: &mut Socket,
) -> Result<(), String> {
    let encrypted_space_size = extract_enum_value!(vsock.read_lv().await?, SetupMessages::EncryptedSpaceAvailable(s) => s)?;
    info!("Encrypted space available = {}B", encrypted_space_size);
    Ok(())
}
