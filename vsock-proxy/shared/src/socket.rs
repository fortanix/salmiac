use byteorder::{
    LittleEndian,
    ReadBytesExt,
    WriteBytesExt
};
use serde::{Serialize};
use serde::de::DeserializeOwned;

use std::io::{
    Read,
    Write
};
use tokio::io::{
    AsyncRead,
    AsyncWrite,
    AsyncReadExt,
    AsyncWriteExt
};
use async_trait::async_trait;

#[async_trait]
pub trait AsyncWriteLvStream : AsyncWrite {
    async fn write_lv_bytes_async(&mut self, data: &[u8]) -> Result<(), String>;

    async fn write_lv_async<T: Serialize + Send + Sync>(&mut self, value: &T) -> Result<(), String>;
}

#[async_trait]
pub trait AsyncReadLvStream : AsyncRead {
    async fn read_lv_bytes_async(&mut self) -> Result<Vec<u8>, String>;

    async fn read_lv_async<T: DeserializeOwned>(&mut self) -> Result<T, String>;
}

#[async_trait]
impl<U> AsyncWriteLvStream for U where U: AsyncWrite + Unpin + Send {
    async fn write_lv_bytes_async(&mut self, data: &[u8]) -> Result<(), String> {
        self.write_u64_le(data.len() as u64)
            .await
            .map_err(|err| format!("Failed to write u64 {:?}", err))?;

        self.write_all(data)
            .await
            .map_err(|err| format!("Failed to write bytes to external socket {:?}", err))
    }

    async fn write_lv_async<T: Serialize + Send + Sync>(&mut self, arg: &T) -> Result<(), String> {
        let bytes = serde_cbor::to_vec(arg)
            .map_err(|err| format!("Failed to serialize struct {:?}", err))?;

        Self::write_lv_bytes_async(self, &bytes).await
    }
}

#[async_trait]
impl<U> AsyncReadLvStream for U where U: AsyncRead + Unpin + Send {
    async fn read_lv_bytes_async(&mut self) -> Result<Vec<u8>, String> {
        let len = self.read_u64_le()
            .await
            .map_err(|err| format!("Failed to read u64 {:?}", err))?;

        let mut buf = vec![0 as u8; len as usize];

        self.read_exact(&mut buf)
            .await
            .map_err(|err| format!("Failed to read data into an array of len {}, error {:?}", buf.len(), err))?;

        Ok(buf)
    }

    async fn read_lv_async<T: DeserializeOwned>(&mut self) -> Result<T, String> {
        let bytes = Self::read_lv_bytes_async(self).await?;

        serde_cbor::from_slice(&bytes)
            .map_err(|err| format!("Failed to deserialize struct {:?}", err))
    }
}

/// Stream abstraction for length-value framing
pub trait LvStream: Read + Write {
    fn read_lv_bytes(&mut self) -> Result<Vec<u8>, String>;

    fn write_lv_bytes(&mut self, data: &[u8]) -> Result<(), String>;

    fn read_lv<T: DeserializeOwned>(&mut self) -> Result<T, String>;

    fn write_lv<T: Serialize>(&mut self, value: &T) -> Result<(), String>;
}

impl<U> LvStream for U where U: Read + Write {
    fn read_lv_bytes(&mut self) -> Result<Vec<u8>, String> {
        let len = self.read_u64::<LittleEndian>()
            .map_err(|err| format!("Failed to read u64 {:?}", err))?;

        let mut buf = vec![0 as u8; len as usize];

        self.read_exact(&mut buf)
            .map_err(|err| format!("Failed to read data into an array of len {}, error {:?}", buf.len(), err))?;

        Ok(buf)
    }

    fn write_lv_bytes(&mut self, data: &[u8]) -> Result<(), String> {
        self.write_u64::<LittleEndian>(data.len() as u64)
            .map_err(|err| format!("Failed to write u64 {:?}", err))?;

        self.write_all(data)
            .map_err(|err| format!("Failed to write bytes to external socket {:?}", err))
    }

    fn read_lv<T: DeserializeOwned>(&mut self) -> Result<T, String> {
        let bytes = Self::read_lv_bytes(self)?;

        serde_cbor::from_slice(&bytes)
            .map_err(|err| format!("Failed to deserialize struct {:?}", err))
    }

    fn write_lv<T: Serialize>(&mut self, arg: &T) -> Result<(), String> {
        let bytes = serde_cbor::to_vec(arg)
            .map_err(|err| format!("Failed to serialize struct {:?}", err))?;

        Self::write_lv_bytes(self, &bytes)
    }
}
