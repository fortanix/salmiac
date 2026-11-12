/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::dsm_key_config::ClientCertificate;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{
    pem::PemObject, CertificateDer, CertificateRevocationListDer, PrivateKeyDer,
};
use rustls::{ClientConfig, RootCertStore};
use simple_hyper_client::blocking::Client;
use simple_hyper_client_rustls::HttpsConnector;
use std::sync::Arc;

pub(crate) fn create_http_client(
    auth_cert: Option<&ClientCertificate>,
    ca_cert_list: Option<Vec<CertificateDer<'static>>>,
    ca_crl: Option<Vec<CertificateRevocationListDer<'static>>>,
) -> Result<Client, String> {
    let config = create_tls_config(auth_cert, ca_cert_list, ca_crl)?;
    Ok(Client::with_connector(HttpsConnector::new(
        tokio_rustls::TlsConnector::from(Arc::new(config)),
    )))
}

fn create_tls_config(
    auth_cert: Option<&ClientCertificate>,
    ca_cert_list: Option<Vec<CertificateDer<'static>>>,
    ca_crl: Option<Vec<CertificateRevocationListDer<'static>>>,
) -> Result<ClientConfig, String> {
    #[cfg(not(debug_assertions))]
    if auth_cert.is_some() && ca_cert_list.is_none() {
        return Err("CA list is required when connecting to DSM".to_string());
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // Explicitly allow TLS 1.2 and 1.3; older TLS versions are never enabled.
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("TLS configuration failed: {e}"))?;

    let mut roots = RootCertStore::empty();
    let certs = match ca_cert_list {
        Some(certs) => certs,
        None => {
            let result = rustls_native_certs::load_native_certs();
            if result.certs.is_empty() {
                return Err(format!(
                    "Unable to load root certificates: {:?}",
                    result.errors
                ));
            }
            result.certs
        }
    };
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| format!("Invalid CA certificate: {e}"))?;
    }
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .with_crls(ca_crl.unwrap_or_default())
        .enforce_revocation_expiration()
        .build()
        .map_err(|e| format!("TLS verifier configuration failed: {e}"))?;
    let builder = builder.with_webpki_verifier(verifier);
    let mut config = match auth_cert {
        Some(auth_cert) => {
            let certs = CertificateDer::pem_slice_iter(auth_cert.certificate.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("Parsing certificate failed: {e}"))?;
            let key = PrivateKeyDer::try_from(auth_cert.key.clone())
                .map_err(|e| format!("Parsing private key failed: {e}"))?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("TLS client certificate configuration failed: {e}"))?
        }
        None => builder.with_no_client_auth(),
    };
    config.enable_sni = true;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ClientConnection, ServerConfig, ServerConnection};
    use std::io::Cursor;

    const CERT: &[u8] = include_bytes!("../resources/test/salmiac-overlayfs-ca-signed-cert.pem");
    const KEY: &[u8] = include_bytes!("../resources/test/salmiac-overlayfs-ca-signed.key");

    #[test]
    #[cfg(not(debug_assertions))]
    fn requires_explicit_ca_list_for_client_certificate() {
        let auth_cert = ClientCertificate {
            certificate: String::from_utf8(CERT.to_vec()).unwrap(),
            key: PrivateKeyDer::from_pem_slice(KEY)
                .unwrap()
                .secret_der()
                .to_vec(),
        };
        assert!(matches!(
            create_tls_config(Some(&auth_cert), None, None),
            Err(err) if err == "CA list is required when connecting to DSM"
        ));
    }

    #[test]
    fn negotiates_tls12_and_tls13_with_sni() {
        let cert = CertificateDer::from_pem_slice(CERT).unwrap();
        let config = Arc::new(create_tls_config(None, Some(vec![cert.clone()]), None).unwrap());
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let server_config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.clone()],
                PrivateKeyDer::from_pem_slice(KEY).unwrap(),
            )
            .unwrap();
            let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut client =
                ClientConnection::new(config.clone(), "localhost".try_into().unwrap()).unwrap();
            let mut hello = Vec::new();
            client.write_tls(&mut hello).unwrap();
            server.read_tls(&mut Cursor::new(hello)).unwrap();
            server.process_new_packets().unwrap();
            assert_eq!(server.protocol_version(), Some(version.version));
            assert_eq!(server.server_name(), Some("localhost"));
        }
    }

    #[test]
    fn loads_and_pass_auth_cert() {
        let auth_cert = ClientCertificate {
            certificate: String::from_utf8(CERT.to_vec()).unwrap(),
            key: PrivateKeyDer::from_pem_slice(KEY)
                .unwrap()
                .secret_der()
                .to_vec(),
        };
        let cert = CertificateDer::from_pem_slice(CERT).unwrap();
        let config = create_tls_config(Some(&auth_cert), Some(vec![cert]), None).unwrap();
        assert!(config.client_auth_cert_resolver.has_certs());
    }
}
