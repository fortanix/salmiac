use std::io;
use std::net::{Shutdown, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use hyper::net::{HttpStream, NetworkStream, SslClient};

use crate::certificate::read_root_certificates;

type TlsStream = rustls::StreamOwned<rustls::ClientSession, HttpStream>;

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

pub struct TlsClient {
    pub cfg: Arc<rustls::ClientConfig>,
}

impl TlsClient {
    pub fn new() -> TlsClient {
        let mut tls_config = rustls::ClientConfig::new();
        let cache = rustls::ClientSessionMemoryCache::new(64);
        tls_config.set_persistence(cache);
        for cert in read_root_certificates() {
            tls_config
                .root_store
                .add(&cert)
                .expect("Failed to add root certificate");
        }

        TlsClient {
            cfg: Arc::new(tls_config),
        }
    }
}

impl SslClient for TlsClient {
    type Stream = WrappedStream;

    fn wrap_client(&self, stream: HttpStream, host: &str) -> hyper::Result<WrappedStream> {
        let dns_name = webpki::DNSNameRef::try_from_ascii_str(host).expect("invalid DNS name");
        let session = rustls::ClientSession::new(&self.cfg, dns_name);
        let tls = rustls::StreamOwned::new(session, stream);

        Ok(WrappedStream(Arc::new(Mutex::new(tls))))
    }
}
