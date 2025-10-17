use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("generic error: {0}")]
    GenericError(String),
}