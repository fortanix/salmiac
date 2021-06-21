use std::net::{TcpListener, UdpSocket, TcpStream};
use vsock::{VsockListener, VsockStream};
use pcap::Packet;
use crate::net::{receive_packet, receive_string, send_packet, BUF_SIZE, receive_u64, send_u64, send_string, send_whole_packet};

pub trait RichListener {
    fn accept_u64(&mut self) -> Result<u64, String>;

    fn accept_packet(&mut self) -> Result<Vec<u8>, String>;

    fn accept_string(&mut self) -> Result<String, String>;
}

pub trait RichSender {
    fn send_u64(&mut self, value : u64) -> Result<(), String>;

    fn send_packet(&mut self, packet : &[u8]) -> Result<(), String>;

    fn send_string(&mut self, data : String) -> Result<(), String>;
}

impl RichListener for VsockStream {
    fn accept_u64(&mut self) -> Result<u64, String> {
        receive_u64(self)
    }

    fn accept_packet(&mut self) -> Result<Vec<u8>, String> {
        receive_packet(self)
    }

    fn accept_string(&mut self) -> Result<String, String> {
        unimplemented!()
    }
}

impl RichSender for VsockStream {
    fn send_u64(&mut self, value: u64) -> Result<(), String> {
        send_u64(self, value)
    }

    fn send_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        send_whole_packet(self, packet)
    }

    fn send_string(&mut self, _data: String) -> Result<(), String> {
        unimplemented!()
    }
}

impl RichListener for UdpSocket {
    fn accept_u64(&mut self) -> Result<u64, String> {
        unimplemented!()
    }

    fn accept_packet(&mut self) -> Result<Vec<u8>, String> {
        unimplemented!()
    }

    fn accept_string(&mut self) -> Result<String, String> {
        loop {
            let mut buf = [0; BUF_SIZE];

            let (amt, _) = self.recv_from(&mut buf).map_err(|err| format!("Cannot read from udp {:?}", err))?;

            let filled_buf = &mut buf[..amt];

            return String::from_utf8(filled_buf.to_vec()).map_err(|err| format!("Cannot parse str {:?}", err))
        }
    }
}

impl RichListener for TcpStream {
    fn accept_u64(&mut self) -> Result<u64, String> {
        unimplemented!()
    }

    fn accept_packet(&mut self) -> Result<Vec<u8>, String> {
        unimplemented!()
    }

    fn accept_string(&mut self) -> Result<String, String> {
        receive_string(self)
    }
}

impl RichSender for TcpStream {
    fn send_u64(&mut self, value: u64) -> Result<(), String> {
        unimplemented!()
    }

    fn send_packet(&mut self, packet: &[u8]) -> Result<(), String> {
        unimplemented!()
    }

    fn send_string(&mut self, data: String) -> Result<(), String> {
        send_string(self, data)
    }
}

pub fn accept_vsock(vsock: &mut VsockListener) -> Result<VsockStream, String> {
    vsock.accept()
        .map(|r| r.0)
        .map_err(|err| format!("Accept from vsock failed: {:?}", err))
}