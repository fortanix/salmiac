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

pub trait RichSocket<T> {
    fn receive(&mut self) -> Result<T, String>;

    fn send(&mut self, arg : T) -> Result<(), String>;
}

impl<T, U> RichSocket<T> for U where U : Read + Write, T : Serialize + DeserializeOwned {
    fn receive(&mut self) -> Result<T, String> {
        let bytes = receive_array(self)?;

        serde_cbor::from_slice(&bytes)
            .map_err(|err| format!("Failed to deserialize struct {:?}", err))
    }

    fn send(&mut self, arg: T) -> Result<(), String> {
        let bytes = serde_cbor::to_vec(&arg)
            .map_err(|err| format!("Failed to serialize struct {:?}", err))?;

        send_array(self, &bytes)
    }
}

fn send_array(writer: &mut dyn Write, data : &[u8]) -> Result<(), String> {
    writer.write_u64::<LittleEndian>(data.len() as u64)
        .map_err(|err| format!("Failed to write u64 {:?}", err))?;

    writer.write_all(data)
        .map_err(|err| format!("Failed to write bytes to external socket {:?}", err))
}

fn receive_array(reader: &mut dyn Read) -> Result<Vec<u8>, String> {
    let len = reader.read_u64::<LittleEndian>()
        .map_err(|err| format!("Failed to read u64 {:?}", err))?;

    let mut buf = vec![0 as u8; len as usize];

    reader.read_exact(&mut buf)
        .map_err(|err| format!("Failed to read data into an array of len {}, error {:?}", buf.len(), err))?;

    Ok(buf)
}