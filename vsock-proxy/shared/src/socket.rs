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
