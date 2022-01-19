use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use std::io;

/// Stream abstraction for length-value framing
#[async_trait]
pub trait AsyncWriteLvStream: AsyncWrite {
    async fn write_lv_bytes(&mut self, data: &[u8]) -> Result<(), String>;

    async fn write_lv<T: Serialize + Send + Sync>(&mut self, value: &T) -> Result<(), String>;
}

#[async_trait]
pub trait AsyncReadLvStream: AsyncRead {
    async fn read_lv_bytes(&mut self) -> Result<Vec<u8>, String>;

    async fn read_lv<T: DeserializeOwned>(&mut self) -> Result<T, String>;
}

#[async_trait]
impl<U> AsyncWriteLvStream for U
where
    U: AsyncWrite + Unpin + Send,
{
    async fn write_lv_bytes(&mut self, data: &[u8]) -> Result<(), String> {
        self.write_u64_le(data.len() as u64)
            .await
            .map_err(|err| format!("Failed to write u64 to vsock. {}", err.to_error_string()))?;

        self.write_all(data)
            .await
            .map_err(|err| format!("Failed to write bytes to vsock. {}", err.to_error_string()))
    }

    async fn write_lv<T: Serialize + Send + Sync>(&mut self, arg: &T) -> Result<(), String> {
        let bytes = serde_cbor::to_vec(arg).map_err(|err| format!("Failed to serialize struct {:?}", err))?;

        Self::write_lv_bytes(self, &bytes).await
    }
}

#[async_trait]
impl<U> AsyncReadLvStream for U
where
    U: AsyncRead + Unpin + Send,
{
    async fn read_lv_bytes(&mut self) -> Result<Vec<u8>, String> {
        let len = self
            .read_u64_le()
            .await
            .map_err(|err| format!("Failed to read u64 from vsock. {}", err.to_error_string()))?;

        let mut buf = vec![0 as u8; len as usize];

        self.read_exact(&mut buf).await.map_err(|err| {
            format!(
                "Failed to read array of len {} from vsock. {}",
                buf.len(),
                err.to_error_string()
            )
        })?;

        Ok(buf)
    }

    async fn read_lv<T: DeserializeOwned>(&mut self) -> Result<T, String> {
        let bytes = Self::read_lv_bytes(self).await?;

        serde_cbor::from_slice(&bytes).map_err(|err| format!("Failed to deserialize struct {:?}", err))
    }
}

trait ErrorString {
    fn to_error_string(&self) -> String;
}

impl ErrorString for io::Error {
    fn to_error_string(&self) -> String {
        match self.kind() {
            io::ErrorKind::NotConnected => {
                format!("No vsock connection between enclave and parent, are they both running?")
            }
            _ => {
                format!("{}", self)
            }
        }
    }
}
