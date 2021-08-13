use byteorder::{
    LittleEndian,
    ByteOrder
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
use std::net::{UdpSocket};
use std::mem;

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

pub struct RichUdp(pub UdpSocket);

impl Read for RichUdp {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv_from(buf).map(|e| e.0)
    }
}

impl Write for RichUdp {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.send(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn send_struct<T : serde::Serialize>(writer: &mut dyn Write, _struct : T) -> Result<(), String> {
    let bytes = bincode::serialize(&_struct)
        .map_err(|err| format!("Failed to serialize struct {:?}", err))?;

    send_whole_array(writer, &bytes)
}

fn receive_struct<T : serde::de::DeserializeOwned>(reader: &mut dyn Read) -> Result<T, String> {
    let bytes = receive_array(reader)?;

    bincode::deserialize(&bytes.clone())
        .map_err(|err| format!("Failed to deserialize struct {:?}", err))
}

fn send_whole_array(writer: &mut dyn Write, packet : &[u8]) -> Result<(), String> {
    send_array(writer, packet, packet.len())
}

fn send_array(writer: &mut dyn Write, data : &[u8], len : usize) -> Result<(), String> {
    let send_length = send_u64(writer, len as u64)
        .map_err(|err| format!("Failure to send packet: {:?}", err));

    send_length.and_then(|_| {
        send_all_bytes(writer, data).map_err(|err| format!("Failure to send packet to vsock: {:?}", err))
    })
}

fn receive_array(reader: &mut dyn Read) -> Result<Vec<u8>, String> {
    let mut buf = [0u8; BUF_SIZE];
    let len = receive_u64(reader).map_err(|err| format!("Failed to receive packet len {:?}", err));

    let packet_raw = len.and_then(|len| {
        receive_bytes0(reader, &mut buf, len).map(|_| len as usize)
    }).map_err(|err| format!("Failed to receive packet {:?}", err));

    packet_raw.map(|len| buf[0..len].to_vec())
}

fn receive_u64(reader: &mut dyn Read) -> Result<u64, String> {
    let mut buf = [0u8; mem::size_of::<u64>()];
    let size = mem::size_of::<u64>() as u64;

    receive_bytes0(reader, &mut buf, size).map(|_e| LittleEndian::read_u64(&buf))
}

fn receive_bytes0(reader: &mut dyn Read, buf: &mut [u8], len: u64) -> Result<(), String> {
    let len = len as usize;
    let mut recv_bytes = 0;

    while recv_bytes < len {
        let size = match reader.read(&mut buf[recv_bytes..len]) {
            Ok(size) => size,
            Err(err) => return Err(format!("{:?}", err)),
        };
        recv_bytes += size;
    }

    Ok(())
}

fn send_u64(writer: &mut dyn Write, val: u64) -> Result<(), String> {
    let mut buf = [0u8; mem::size_of::<u64>()];
    LittleEndian::write_u64(&mut buf, val);

    send_all_bytes(writer, &mut buf)
}

fn send_all_bytes(writer: &mut dyn Write, buf: &[u8]) -> Result<(), String> {
    writer.write_all(buf).map_err(|err| format!("Failed to write bytes to external socket {:?}", err))
}