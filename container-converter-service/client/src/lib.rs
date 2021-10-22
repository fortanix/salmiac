#![deny(warnings)]
#[cfg(feature = "hyper-native-tls")]
extern crate hyper_native_tls;
#[macro_use]
extern crate log;

mod client;
pub mod error;
mod generated;
pub mod operations;
#[cfg(feature="mock")]
pub mod mock;

pub use error::Error;
pub use client::*;

pub type Result<T> = std::result::Result<T, Error>;
