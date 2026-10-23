use std::io;
use std::net::{Shutdown, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use hyper::net::{HttpStream, NetworkStream, SslClient};

use crate::certificate::read_root_certificates;

pub struct TlsStream {
    sess: Box<dyn rustls::Session>,
    underlying: HttpStream,
    eof: bool,
    tls_error: Option<rustls::TLSError>,
    io_error: Option<io::Error>,
}

impl TlsStream {
    fn underlying_read(&mut self) {
        if self.io_error.is_some() || self.tls_error.is_some() {
            return;
        }

        if self.sess.wants_read() {
            match self.sess.read_tls(&mut self.underlying) {
                Err(err) => {
                    if err.kind() != io::ErrorKind::WouldBlock {
                        self.io_error = Some(err);
                    }
                }
                Ok(0) => {
                    self.eof = true;
                }
                Ok(_) => (),
            }
        }

        if let Err(err) = self.sess.process_new_packets() {
            self.tls_error = Some(err);
        }
    }

    fn underlying_write(&mut self) {
        if self.io_error.is_some() || self.tls_error.is_some() {
            return;
        }

        while self.io_error.is_none() && self.sess.wants_write() {
            if let Err(err) = self.sess.write_tls(&mut self.underlying) {
                if err.kind() != io::ErrorKind::WouldBlock {
                    self.io_error = Some(err);
                }
            }
        }
    }

    fn underlying_io(&mut self) {
        self.underlying_write();
        self.underlying_read();
    }

    fn promote_tls_error(&mut self) -> io::Result<()> {
        match self.tls_error.take() {
            Some(err) => Err(io::Error::new(io::ErrorKind::ConnectionAborted, err)),
            None => Ok(()),
        }
    }

    fn check_io_error(&mut self) -> io::Result<()> {
        self.io_error.take().map(Err).unwrap_or(Ok(()))
    }

    fn close(&mut self, how: Shutdown) -> io::Result<()> {
        self.underlying.close(how)
    }

    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.underlying.peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.underlying.set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.underlying.set_write_timeout(dur)
    }
}

impl io::Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // This wants to block if we don't have any data ready.
        // underlying_read does this.
        loop {
            self.promote_tls_error()?;
            self.check_io_error()?;

            if self.eof {
                return Ok(0);
            }

            match self.sess.read(buf) {
                Ok(0) => self.underlying_io(),
                Ok(n) => return Ok(n),
                Err(e) => return Err(e),
            }
        }
    }
}

impl io::Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self.sess.write(buf)?;
        self.promote_tls_error()?;
        self.underlying_write();
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        let rc = self.sess.flush();
        self.promote_tls_error()?;
        self.underlying_write();
        rc
    }
}

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
        self.lock().peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.lock().set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.lock().set_write_timeout(dur)
    }

    fn close(&mut self, how: Shutdown) -> io::Result<()> {
        self.lock().close(how)
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
        let tls = TlsStream {
            sess: Box::new(rustls::ClientSession::new(&self.cfg, dns_name)),
            underlying: stream,
            eof: false,
            io_error: None,
            tls_error: None,
        };

        Ok(WrappedStream(Arc::new(Mutex::new(tls))))
    }
}
