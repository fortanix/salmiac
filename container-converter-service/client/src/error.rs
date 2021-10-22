use std::{error, io, fmt};
use hyper;
use hyper::status::StatusCode;
#[cfg(feature = "hyper-native-tls")]
use hyper_native_tls::native_tls;

#[derive(Debug)]
pub enum Error {
    Unauthorized(String),
    Forbidden(String),
    BadRequest(String),
    Conflict(String),
    Locked(String),
    NotFound(String),
    StatusCode(String),
    SessionError(String),
    EncoderError(serde_json::error::Error),
    IoError(io::Error),
    NetworkError(hyper::Error),
#[cfg(feature = "hyper-native-tls")]
    TlsError(native_tls::Error),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "nitro-enclaves-converter-client error"
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NotFound(ref msg) => write!(fmt, "{}", msg),
            Error::Unauthorized(ref msg) => write!(fmt, "{}", msg),
            Error::Forbidden(ref msg) => write!(fmt, "{}", msg),
            Error::BadRequest(ref msg) => write!(fmt, "{}", msg),
            Error::Conflict(ref msg) => write!(fmt, "{}", msg),
            Error::Locked(ref msg) => write!(fmt, "{}", msg),
            Error::SessionError(ref msg) => write!(fmt, "{}", msg),
            Error::EncoderError(ref err) => write!(fmt, "{}", err),
            Error::IoError(ref err) => write!(fmt, "{}", err),
            Error::NetworkError(ref err) => write!(fmt, "{}", err),
            #[cfg(feature = "hyper-native-tls")]
            Error::TlsError(ref err) => write!(fmt, "{}", err),
            Error::StatusCode(ref msg) => write!(fmt, "unexpected status code: {}", msg),
        }
    }
}

impl Error {
    pub fn from_status(status: StatusCode, msg: String) -> Self {
        match status {
            StatusCode::Unauthorized => Error::Unauthorized(msg),
            StatusCode::Forbidden => Error::Forbidden(msg),
            StatusCode::BadRequest => Error::BadRequest(msg),
            StatusCode::Conflict => Error::Conflict(msg),
            StatusCode::Locked => Error::Locked(msg),
            StatusCode::NotFound => Error::NotFound(msg),
            _ => Error::StatusCode(format!("{}\n{}", status.to_string(), msg)),
        }
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(error: serde_json::error::Error) -> Error {
        Error::EncoderError(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::IoError(error)
    }
}

impl From<hyper::Error> for Error {
    fn from(error: hyper::Error) -> Error {
        Error::NetworkError(error)
    }
}

#[cfg(feature = "hyper-native-tls")]
impl From<native_tls::Error> for Error {
    fn from(error: native_tls::Error) -> Error {
        Error::TlsError(error)
    }
}

pub fn session_error<T: Into<String>>(msg: T) -> Error {
    Error::SessionError(msg.into())
}