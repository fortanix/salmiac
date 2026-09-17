use std::sync::Arc;

use api_model::enclave::CcmBackendUrl;
use em_client::client::Client as EmClient;
use em_client::models::ApplicationConfigSdkmsCredentials;
use hyper::client::{Client, Pool};
use hyper::net::HttpsConnector;
use hyper_rustls::TlsClient;
use sdkms::SdkmsClient;

use crate::app_configuration::EmAppCredentials;

// This the counterpart of how em_app configures tls connection.
// For the security reasons rustls's TlsClient should be configured
// in a similar fashion.
// Reference: https://github.com/fortanix/rust-sgx/blob/5d33ab498ec96a7a429816501287f790a2b5bcfe/em-app/src/utils.rs#L53
//
// `ca_cert_list`
// em_app sets to `AuthMode::Required` only when `ca_cert_list` is provided.
// For rustls, if `ca_cert_list` is not provided, rustls always do checks against the
// default CA list.
// Reference: https://docs.rs/crate/hyper-rustls/0.6.2/source/src/lib.rs#200
// To disable completely `DangerousClientConfig` must be used:
// Reference: https://docs.rs/crate/rustls/0.13.1/source/src/client/mod.rs#209
//
// Tls version 1.2
// em_app explicitly sets to tls version 1.2 However rustls by default expects
// tls 1.2 or 1.3.
// Reference: https://docs.rs/crate/rustls/0.13.1/source/src/client/mod.rs#144
//
// SNI configuration is ignored for now.
pub fn get_hyper_tls_connector(
    credentials: &EmAppCredentials,
) -> Result<HttpsConnector<TlsClient>, String> {
    let mut ssl = TlsClient::new();
    let tls_config = Arc::get_mut(&mut ssl.cfg).expect("TlsClient config unexpectedly shared");

    if let Some(root_cert) = &credentials.root_certificate {
        for cert in root_cert {
            tls_config
                .root_store
                .add(cert)
                .map_err(|err| format!("Unable to add CCM root cert: {:?}", err))?;
        }
    }

    tls_config.set_single_client_cert(credentials.certificate.clone(), credentials.key.clone());

    Ok(HttpsConnector::new(ssl))
}

pub fn get_em_client(
    ccm_backend_url: &CcmBackendUrl,
    connector: HttpsConnector<TlsClient>,
) -> Result<EmClient, String> {
    let em_client =
        EmClient::try_new_with_connector(&ccm_backend_url.to_string(), Some("https"), connector)
            .map_err(|err| format!("Unable to construct em_client: {}", err))?;
    Ok(em_client)
}

pub fn get_sdkms_client(
    sdkms_credentials: &ApplicationConfigSdkmsCredentials,
    connector: HttpsConnector<TlsClient>,
) -> Result<SdkmsClient, String> {
    let client = Arc::new(Client::with_connector(Pool::with_connector(
        Default::default(),
        connector,
    )));
    // em-client and sdkms use different versions of uuid.
    let app_id = sdkms_credentials
        .sdkms_app_id
        .to_string()
        .parse()
        .map_err(|err| format!("Invalid SDKMS app ID: {}", err))?;
    let client = SdkmsClient::builder()
        .with_api_endpoint(&sdkms_credentials.credentials_url)
        .with_hyper_client(client)
        .build()
        .map_err(|err| format!("SDKMS Build failed: {:?}", err))?
        .authenticate_with_cert(Some(&app_id))
        .map_err(|err| format!("SDKMS authenticate failed: {:?}", err))?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use hyper::status::StatusCode;
    use mbedtls::{
        hash::Type,
        pk::Pk,
        rng::Rdrand,
        x509::{certificate::Builder, KeyUsage, Time},
    };
    use pkix::types::{GeneralName, GeneralNames, ObjectIdentifier, TaggedDerValue};
    use pkix::{FromDer, ToDer};
    use rustls::{Certificate, PrivateKey};
    use std::io::Read;
    use std::str::FromStr;
    use std::time::Duration;
    use test_case::test_case;

    use super::get_hyper_tls_connector;
    use crate::app_configuration::EmAppCredentials;
    use crate::certificate::create_signer_key;

    const TIMEOUT: Duration = Duration::from_secs(10);

    // Creates a test certificate to be used by both client & server
    fn test_certificate(key_der: &[u8], is_ca: bool, padding: usize) -> Certificate {
        let mut subject_key = Pk::from_private_key(key_der, None).unwrap();
        let mut issuer_key = Pk::from_private_key(key_der, None).unwrap();
        let mut cert = Builder::new();
        cert.subject_key(&mut subject_key)
            .issuer_key(&mut issuer_key)
            .signature_hash(Type::Sha256);
        cert.subject(if is_ca { "CN=Test CA" } else { "CN=localhost" })
            .unwrap();
        cert.issuer("CN=Test CA").unwrap();
        cert.serial(&[1]).unwrap();
        cert.validity(
            Time::new(2020, 1, 1, 0, 0, 0).unwrap(),
            Time::new(2099, 1, 1, 0, 0, 0).unwrap(),
        )
        .unwrap();
        cert.basic_constraints(is_ca, None).unwrap();
        cert.key_usage(if is_ca {
            KeyUsage::KEY_CERT_SIGN
        } else {
            KeyUsage::DIGITAL_SIGNATURE
        })
        .unwrap();
        let san = GeneralNames(vec![GeneralName::DnsName("localhost".into())]).to_der();
        cert.extension(b"\x55\x1d\x11", &san, false).unwrap(); // subjectAltName
        if padding > 0 {
            let fortanix_oid = ObjectIdentifier::from_str("1.3.6.1.4.1.49690.999.1").unwrap();
            let encoded_oid = TaggedDerValue::from_der(&fortanix_oid.to_der()).unwrap();
            cert.extension(encoded_oid.value(), &vec![0u8; padding].to_der(), false)
                .unwrap();
        }
        Certificate(cert.write_der_vec(&mut Rdrand).unwrap())
    }

    #[test_case(16, true; "minimum 16KB")]
    #[test_case(24, true; "minimum 24KB")]
    #[test_case(48, true; "minimum 48KB")]
    #[test_case(64, false; "minimum 64KB")]
    fn test_certificate_size_in_https_request(padding: usize, should_succeed: bool) {
        let key = create_signer_key(2048)
            .unwrap()
            .write_private_der_vec()
            .unwrap();
        let ca_cert = test_certificate(&key, true, 0);
        let server_cert = test_certificate(&key, false, 0);
        let private_key = PrivateKey(key);

        let client_cert = test_certificate(&private_key.0, false, padding * 1024);
        let credentials = EmAppCredentials {
            certificate: vec![client_cert.clone()],
            key: private_key.clone(),
            root_certificate: Some(vec![ca_cert.clone()]),
        };
        let connector = get_hyper_tls_connector(&credentials).unwrap();
        let mut client = hyper::Client::with_connector(connector);
        client.set_read_timeout(Some(TIMEOUT));
        client.set_write_timeout(Some(TIMEOUT));

        let (port, server) =
            server::create_rustls_server(ca_cert, server_cert, private_key, client_cert);
        let response = client.get(&format!("https://localhost:{}/", port)).send();

        // Join before checking response, so the server doesn't leak.
        let server_result = server.join().expect("TLS server panicked");
        if !should_succeed {
            let err = server_result.expect_err("Oversized certificate was accepted");
            let rustls_err = err
                .get_ref()
                .and_then(|err| err.downcast_ref::<rustls::TLSError>());
            assert!(
                matches!(rustls_err, Some(rustls::TLSError::CorruptMessagePayload(_))),
                "Unexpected TLS error: {:?}",
                err
            );
            assert!(
                response.is_err(),
                "HTTPS request with 64 KiB certificate padding succeeded"
            );
            return;
        }
        let mut response = response.expect("HTTPS request with large client certificate failed");
        server_result.expect("TLS server failed");
        assert_eq!(response.status, StatusCode::Ok);

        // Check HTTP body
        let mut body = String::new();
        response.read_to_string(&mut body).unwrap();
        assert_eq!(body, "OK");
    }

    mod server {
        use std::io::{ErrorKind, Read, Write};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread::{self, JoinHandle};
        use std::time::{Duration, Instant};

        use rustls::{
            AllowAnyAuthenticatedClient, Certificate, PrivateKey, ProtocolVersion, RootCertStore,
            ServerConfig, ServerSession, Session, StreamOwned,
        };

        use super::TIMEOUT;

        const HTTP_LINE_ENDING: &[u8] = b"\r\n\r\n";
        const HTTP_START: &[u8] = b"GET / HTTP/1.1\r\n";
        const HTTP_END: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";

        // Starts a rustls based http server
        pub fn create_rustls_server(
            ca_cert: Certificate,
            server_cert: Certificate,
            private_key: PrivateKey,
            client_cert: Certificate,
        ) -> (u16, JoinHandle<std::io::Result<()>>) {
            let mut roots = RootCertStore::empty();
            roots.add(&ca_cert).unwrap();
            let mut config = ServerConfig::new(AllowAnyAuthenticatedClient::new(roots));
            config.versions = vec![ProtocolVersion::TLSv1_2];
            config
                .set_single_cert(vec![server_cert], private_key)
                .unwrap();

            // Configure listener
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            // Set to nonblocking to keep an eye on timeout
            listener.set_nonblocking(true).unwrap();

            let server = thread::spawn(move || {
                let deadline = Instant::now() + TIMEOUT;
                let socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(err) if err.kind() == ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "TLS client did not connect");
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(err) => panic!("TLS listener failed: {}", err),
                    }
                };

                // Set timeouts
                socket.set_read_timeout(Some(TIMEOUT)).unwrap();
                socket.set_write_timeout(Some(TIMEOUT)).unwrap();

                let session = ServerSession::new(&Arc::new(config));
                let mut tls = StreamOwned::new(session, socket);
                let mut request = Vec::new();
                while !request.ends_with(HTTP_LINE_ENDING) {
                    let mut byte = [0];
                    // Reading makes TLS handshake to proceed
                    tls.read_exact(&mut byte)?;
                    request.push(byte[0]);
                    assert!(request.len() < 8192);
                }
                assert!(request.starts_with(HTTP_START));
                assert_eq!(tls.sess.get_peer_certificates().unwrap(), vec![client_cert]);
                tls.write_all(HTTP_END)?;
                tls.flush()
            });

            (port, server)
        }
    }
}
