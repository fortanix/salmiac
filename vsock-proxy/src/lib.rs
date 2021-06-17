pub mod net;

use std::net::{
    Ipv4Addr,
    UdpSocket
};

use nix::sys::socket::SockAddr;
use vsock::{
    VsockListener,
    VsockStream
};
use pcap::Active;


const VSOCK_PARENT_CID: u32 = 3; // from AWS Nitro documentation

pub struct Proxy {
    local_port: u32,
    cid : u32,
    remote_port: u16,
}

impl Proxy {
    pub fn new(local_port: u32, cid : u32, remote_port: u16) -> Self {
        Proxy {
            local_port,
            cid,
            remote_port,
        }
    }

    pub fn open_packet_capture(&self) -> Result<pcap::Capture<Active>, String> {
        net::open_packet_capture(self.remote_port as u32)
    }

    pub fn listen_parent(&self) -> Result<VsockListener, String> {
        let sockaddr = SockAddr::new_vsock(self.cid, self.local_port);

        VsockListener::bind(&sockaddr).map_err(|_| format!("Could not bind to {:?}", sockaddr))
    }

    pub fn connect_to_enclave(&self) -> Result<VsockStream, String> {
        let sockaddr = SockAddr::new_vsock(self.cid, self.local_port);

        VsockStream::connect(&sockaddr).map_err(|err| format!("Failed to connect to enclave: {:?}", err))
    }

    /*pub fn listen_remote_tcp(&self) -> Result<TcpListener, String> {
        let sock_addr = SocketAddr::new(self.remote_addr, self.remote_port);

        TcpListener::bind(sock_addr).map_err(|err| format!("Failed to listen to external port {:?}", err))
    }

    pub fn connect_remote_tcp(&self) -> Result<TcpStream, String> {
        let sock_addr = SocketAddr::new(self.remote_addr, self.remote_port);

        TcpStream::connect(sock_addr).map_err(|err| format!("Failed to connect to external port {:?}", err))
    }*/
}

pub fn bind_udp(port : u16) -> Result<UdpSocket, String> {
    UdpSocket::bind(format!("{}:{}", Ipv4Addr::UNSPECIFIED, port)).map_err(|err| format!("Failed to connect to external port {:?}", err))
}


