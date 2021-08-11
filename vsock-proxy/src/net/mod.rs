pub mod socket_extensions;
pub mod netlink;
pub mod packet_capture;
pub mod device;

use std::io::{
    Read,
    Write
};
use std::mem;

use byteorder::{
    LittleEndian,
    ByteOrder
};

pub const BUF_SIZE : usize = 4096;

pub fn send_struct<T : serde::Serialize>(writer: &mut dyn Write, _struct : T) -> Result<(), String> {
    let bytes = bincode::serialize(&_struct).map_err(|err| format!("Failed to serialize struct {:?}", err))?;

    send_whole_packet(writer, &bytes)
}

pub fn receive_struct<T : serde::de::DeserializeOwned>(reader: &mut dyn Read) -> Result<T, String> {
    let bytes = receive_packet(reader)?;

    bincode::deserialize(&bytes.clone()).map_err(|err| format!("Failed to deserialize struct {:?}", err))
}

pub fn send_whole_packet(writer: &mut dyn Write, packet : &[u8]) -> Result<(), String> {
    send_packet(writer, packet, packet.len())
}

pub fn send_packet(writer: &mut dyn Write, data : &[u8], len : usize) -> Result<(), String> {
    let send_length = send_u64(writer, len as u64)
        .map_err(|err| format!("Failure to send packet to vsock: {:?}", err));

    send_length.and_then(|_| {
        send_all_bytes(writer, data).map_err(|err| format!("Failure to send packet to vsock: {:?}", err))
    })
}

pub fn receive_packet(reader: &mut dyn Read) -> Result<Vec<u8>, String> {
    let mut buf = [0u8; BUF_SIZE];
    let len = receive_u64(reader).map_err(|err| format!("Failed to receive packet len {:?}", err));

    let packet_raw = len.and_then(|len| {
        receive_bytes0(reader, &mut buf, len).map(|_| len as usize)
    }).map_err(|err| format!("Failed to receive packet {:?}", err));

    packet_raw.map(|len| buf[0..len].to_vec())
}

pub fn send_string(tcp: &mut dyn Write, data : String) -> Result<(), String> {
    let buf = data.as_bytes();
    let len = buf.len() as u64;

    send_u64(tcp, len).and_then(|_e| send_all_bytes(tcp, &buf))
}

pub fn receive_string(reader:&mut dyn Read) -> Result<String, String> {
    receive_packet(reader).and_then(|packet| {
        String::from_utf8(packet).map_err(|err| format!("The received bytes are not UTF-8: {:?}", err))
    })
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

pub fn send_u64(writer: &mut dyn Write, val: u64) -> Result<(), String> {
    let mut buf = [0u8; mem::size_of::<u64>()];
    LittleEndian::write_u64(&mut buf, val);

    send_all_bytes(writer, &mut buf)
}

fn send_all_bytes(writer: &mut dyn Write, buf: &[u8]) -> Result<(), String> {
    writer.write_all(buf).map_err(|err| format!("Failed to write bytes to external socket {:?}", err))
}