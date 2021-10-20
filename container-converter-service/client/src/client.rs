use crate::{Result};
use crate::error::Error;
use crate::operations::*;

#[cfg(feature = "hyper-native-tls")]
use hyper::client::Pool;
use hyper::header::ContentType;
use hyper::method::Method;
#[cfg(feature = "hyper-native-tls")]
use hyper::net::HttpsConnector;
use hyper::Client as HyperClient;
use hyper::client::Response;
#[cfg(feature = "hyper-native-tls")]
use hyper_native_tls::NativeTlsClient;
use serde::{Deserialize, Serialize};

use std::io::Read;
use std::sync::Arc;


pub struct NitroEnclavesConverterClientBuilder {
    client: Option<Arc<HyperClient>>,
    api_endpoint: Option<String>,
    error_retry_attempts: Option<usize>,
}

impl NitroEnclavesConverterClientBuilder {
    /// This can be used to customize the underlying HTTPS client if desired.
    pub fn with_hyper_client(mut self, client: Arc<HyperClient>) -> Self {
        self.client = Some(client);
        self
    }

    /// This can be used to set the API endpoint.
    pub fn with_api_endpoint<T: Into<String>>(mut self, api_endpoint: T) -> Self {
        self.api_endpoint = Some(api_endpoint.into());
        self
    }

    /// The number of times to retry a request in case of a recoverable network error. Defaults
    /// to 0.
    pub fn with_error_retry_attempts(mut self, error_retry_attempts: usize) -> Self {
        self.error_retry_attempts = Some(error_retry_attempts);
        self
    }

    /// Build [`NitroEnclavesConverterClient`](./struct.NitroEnclavesConverterClient.html)
    pub fn build(self) -> Result<NitroEnclavesConverterClient> {
        let client = match self.client {
            Some(client) => client,
            None => {
                #[cfg(feature = "hyper-native-tls")]
                {
                    let ssl = NativeTlsClient::new()?;
                    let connector = HttpsConnector::new(ssl);
                    let client = HyperClient::with_connector(Pool::with_connector(Default::default(), connector));
                    Arc::new(client)
                }
                #[cfg(not(feature = "hyper-native-tls"))]
                panic!("You should either provide a hyper Client or compile this crate with hyper-native-tls feature");
            }
        };

        Ok(NitroEnclavesConverterClient {
            client,
            api_endpoint: self.api_endpoint.unwrap(),
            error_retry_attempts: self.error_retry_attempts.unwrap_or(0),
        })
    }
}

pub struct NitroEnclavesConverterClient {
    client: Arc<HyperClient>,
    api_endpoint: String,
    error_retry_attempts: usize,
}

impl NitroEnclavesConverterClient {
    pub fn builder() -> NitroEnclavesConverterClientBuilder {
        NitroEnclavesConverterClientBuilder {
            client: None,
            api_endpoint: None,
            error_retry_attempts: None,
        }
    }

    pub fn api_endpoint(&self) -> &str {
        &self.api_endpoint
    }
}

impl NitroEnclavesConverterClient {
    pub fn execute<O: Operation>(
        &self,
        body: &O::Body,
        p: <O::PathParams as TupleRef>::Ref,
        q: Option<&O::QueryParams>,
    ) -> Result<O::Output> {
        let (output, _) = json_request(&self.client, &self.api_endpoint, O::method(), &O::path(p, q), O::to_body(body).as_ref(), self.error_retry_attempts)?;
        Ok(output)
    }
}

fn json_decode_reader<R: Read, T: for<'de> Deserialize<'de>>(rdr: &mut R) -> serde_json::Result<T> {
    match serde_json::from_reader(rdr) {
        // When the body of the response is empty, attempt to deserialize null value instead
        Err(ref e) if e.is_eof() && e.line() == 1 && e.column() == 0 => {
            serde_json::from_value(serde_json::Value::Null)
        }
        v => v,
    }
}

fn json_request<E, D>(
    client: &HyperClient,
    api_endpoint: &str,
    method: Method,
    path: &str,
    body: Option<&E>,
    retries: usize,
) -> Result<(D, Response)>
where
    E: Serialize,
    D: for<'de> Deserialize<'de>,
{
    let url = format!("{}{}", api_endpoint, path);
    let encoded_body = body.map(serde_json::to_string).transpose().map_err(Error::EncoderError)?;

    let mut attempt = 0;
    loop {
        let mut req_builder = client.request(method.clone(), &url);
        if let Some(encoded_body) = encoded_body.as_ref() {
            req_builder = req_builder.header(ContentType::json());
            req_builder = req_builder.body(encoded_body.as_bytes())
        }
        match req_builder.send() {
            Err(e) => {
                if !is_retryable_error(&e) {
                    warn!("Error {} {}: {:?}", method, url, e);
                    return Err(Error::NetworkError(e));
                }
                warn!("Retryable error (attempt {} of {}) {} {}: {:?}", attempt + 1, retries + 1, method, url, e);
                if attempt == retries {
                    return Err(Error::NetworkError(e));
                }
                attempt += 1;
            }
            Ok(mut res) if res.status.is_success() => {
                info!("{} {} {}", res.status.to_u16(), method, url);
                let body: D = json_decode_reader(&mut res).map_err(|err| Error::EncoderError(err))?;
                return Ok((body, res))
            }
            Ok(ref mut res) => {
                info!("{} {} {}", res.status.to_u16(), method, url);
                let mut buffer = String::new();
                res.read_to_string(&mut buffer).map_err(|err| Error::IoError(err))?;
                return Err(Error::from_status(res.status, buffer))
            }
        }
    }
}

fn is_retryable_error(e: &hyper::Error) -> bool {
    matches!(e, hyper::Error::Io(_)) ||
        matches!(e, hyper::Error::Ssl(err) if err.to_string() == "ctx.establish failed: mbedTLS error SslConnEof")
}