use std::convert::TryFrom;
use std::io;
use std::net::{Shutdown, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use hyper_v0::net::{HttpStream, NetworkStream, SslClient};
use hyper_v0::Result as HyperResult;

use crate::app_configuration::EmAppCredentials;
use crate::certificate::read_root_certificates;
use rustls::pki_types::ServerName;

type TlsStream = rustls::StreamOwned<rustls::ClientConnection, HttpStream>;

#[derive(Clone)]
pub struct WrappedStream(Arc<Mutex<TlsStream>>);

impl WrappedStream {
    fn lock(&self) -> MutexGuard<'_, TlsStream> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl io::Read for WrappedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.lock().read(buf)
    }
}

impl io::Write for WrappedStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.lock().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.lock().flush()
    }
}

impl NetworkStream for WrappedStream {
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.lock().sock.peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.lock().sock.set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.lock().sock.set_write_timeout(dur)
    }

    fn close(&mut self, how: Shutdown) -> io::Result<()> {
        self.lock().sock.close(how)
    }
}

// TODO: RTE-1166 hyper upgrade should replace this
// type with corresponding type in hyper-rustls
pub struct TlsClient {
    pub cfg: Arc<rustls::ClientConfig>,
}

impl TlsClient {
    pub fn new(credentials: Option<&EmAppCredentials>) -> Result<TlsClient, String> {
        let mut roots = rustls::RootCertStore::empty();
        let mut root_certs = read_root_certificates();

        // Add credentials' root certificates if available
        if let Some(credential_certs) =
            credentials.and_then(|creds| creds.root_certificate.as_ref())
        {
            root_certs.extend(credential_certs.into_iter().cloned());
        }

        for cert in root_certs {
            roots
                .add(cert)
                .map_err(|e| format!("Unable to add root certificate: {e}"))?;
        }
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("TLS configuration failed: {e}"))?
        .with_root_certificates(roots);

        let mut config = match credentials {
            Some(credentials) => builder
                .with_client_auth_cert(credentials.certificate.clone(), credentials.key.clone_key())
                .map_err(|e| format!("TLS client certificate configuration failed: {e}"))?,
            None => builder.with_no_client_auth(),
        };
        config.resumption = rustls::client::Resumption::in_memory_sessions(64);

        Ok(TlsClient {
            cfg: Arc::new(config),
        })
    }
}

impl SslClient for TlsClient {
    type Stream = WrappedStream;

    fn wrap_client(&self, stream: HttpStream, host: &str) -> HyperResult<WrappedStream> {
        let server_name =
            ServerName::try_from(host.to_owned()).map_err(|e| hyper_v0::Error::Ssl(Box::new(e)))?;
        let session = rustls::ClientConnection::new(self.cfg.clone(), server_name)
            .map_err(|e| hyper_v0::Error::Ssl(Box::new(e)))?;
        let tls = rustls::StreamOwned::new(session, stream);

        Ok(WrappedStream(Arc::new(Mutex::new(tls))))
    }
}
