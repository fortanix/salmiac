use byteorder::{
    LittleEndian,
    ReadBytesExt,
    WriteBytesExt
};
use serde::{Serialize};
use serde::de::DeserializeOwned;
use vsock::{
    VsockListener,
    VsockStream
};

use std::io::{
    Read,
    Write
};

pub const BUF_SIZE : usize = 4096;

pub fn accept_vsock(vsock: &mut VsockListener) -> Result<VsockStream, String> {
    vsock.accept()
        .map(|r| r.0)
        .map_err(|err| format!("Accept from vsock failed: {:?}", err))
}

pub trait RichSocket<T> {
    fn receive(&mut self) -> Result<T, String>;

    fn send(&mut self, arg : T) -> Result<(), String>;
}

impl<T, U> RichSocket<T> for U where U : Read + Write, T : Serialize + DeserializeOwned {
    fn receive(&mut self) -> Result<T, String> {
        receive_struct(self)
    }

    fn send(&mut self, arg: T) -> Result<(), String> {
        send_struct(self, arg)
    }
}

fn send_struct<T : serde::Serialize>(writer: &mut dyn Write, _struct : T) -> Result<(), String> {
    let bytes = bincode::serialize(&_struct)
        .map_err(|err| format!("Failed to serialize struct {:?}", err))?;

    send_array(writer, &bytes)
}

fn receive_struct<T : serde::de::DeserializeOwned>(reader: &mut dyn Read) -> Result<T, String> {
    let bytes = receive_array(reader)?;

    bincode::deserialize(&bytes.clone())
        .map_err(|err| format!("Failed to deserialize struct {:?}", err))
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