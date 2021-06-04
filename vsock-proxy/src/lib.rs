use nix::sys::socket::{SockAddr};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, TcpListener};
use vsock::{VsockListener, VsockStream};

pub const VSOCK_PROXY_CID: u32 = 3; // from AWS Nitro documentation

pub const VSOCK_ANY_CID : u32 = 0xFFFFFFFF;

pub struct Proxy {
    local_port: u32,
    remote_addr: IpAddr,
    remote_port: u16,
}

impl Proxy {
    pub fn new(local_port: u32, remote_addr: IpAddr, remote_port: u16) -> Self {
        Proxy {
            local_port,
            remote_addr,
            remote_port,
        }
    }

    pub fn listen_enclave(&self) -> Result<VsockListener, String> {
        let sockaddr = SockAddr::new_vsock(VSOCK_ANY_CID, self.local_port);

        VsockListener::bind(&sockaddr).map_err(|_| format!("Could not bind to {:?}", sockaddr))
    }

    pub fn connect_enclave(&self, cid: u32) -> Result<VsockStream, String> {
        let sockaddr = SockAddr::new_vsock(cid, self.local_port);

        VsockStream::connect(&sockaddr).map_err(|err| format!("Failed to connect to enclave: {:?}", err))
    }

    pub fn listen_remote(&self) -> Result<TcpListener, String> {
        let sock_addr = SocketAddr::new(self.remote_addr, self.remote_port);

        TcpListener::bind(sock_addr).map_err(|err| format!("Failed to listen to external port {:?}", err))
    }

    pub fn connect_remote(&self) -> Result<TcpStream, String> {
        let sock_addr = SocketAddr::new(self.remote_addr, self.remote_port);

        TcpStream::connect(sock_addr).map_err(|err| format!("Failed to connect to external port {:?}", err))
    }
}

pub fn transfer_to_enclave(vsock : &mut VsockStream, listener : &mut TcpListener) -> Result<(), String> {
    loop {
        let (mut incoming, _) = listener.accept().map_err(|err| format!("Accept from external socket failed: {:?}", err))?;

        let received = receive_string(&mut incoming);

        let r = received.and_then(|r| {
            println!("{}", r);
            send_string(vsock, r)
        });

        return r;
    }
}

pub fn accept_string(listener : &mut VsockListener) -> Result<String, String> {
    loop {
        let (mut incoming, _) = listener.accept().map_err(|err| format!("Accept from enclave socket failed: {:?}", err))?;

        return receive_string(&mut incoming);
    }
}

fn receive_string(tcp :&mut dyn Read) -> Result<String, String> {
    let len = receive_u64(tcp)?;
    let mut buf = [0u8; 8192];
    receive_bytes(tcp, &mut buf, len)?;

    let received = String::from_utf8(buf.to_vec()).map_err(|err| format!("The received bytes are not UTF-8: {:?}", err));

    received
}

fn receive_bytes(tcp: &mut dyn Read, buf: &mut [u8], len: u64) -> Result<(), String> {
    let len = len as usize;
    let mut recv_bytes = 0;

    while recv_bytes < len {
        let size = match tcp.read(&mut buf[recv_bytes..len]) {
            Ok(size) => size,
            Err(err) => return Err(format!("{:?}", err)),
        };
        recv_bytes += size;
    }

    Ok(())
}

fn receive_u64(tcp: &mut dyn Read) -> Result<u64, String> {
    use std::mem::size_of;
    use byteorder::LittleEndian;
    use byteorder::ByteOrder;

    let mut buf = [0u8; size_of::<u64>()];
    let size = size_of::<u64>() as u64;

    receive_bytes(tcp, &mut buf, size).map(|_e| LittleEndian::read_u64(&buf))
}

fn send_u64(tcp: &mut dyn Write, val: u64) -> Result<(), String> {
    use std::mem::size_of;
    use byteorder::LittleEndian;
    use byteorder::ByteOrder;

    let mut buf = [0u8; size_of::<u64>()];
    LittleEndian::write_u64(&mut buf, val);

    send_bytes(tcp, &mut buf)
}

pub fn send_string(tcp: &mut dyn Write, data : String) -> Result<(), String> {
    let buf = data.as_bytes();
    let len = buf.len() as u64;

    send_u64(tcp, len).and_then(|_e| send_bytes(tcp, &buf))
}

fn send_bytes(tcp: &mut dyn Write, buf: &[u8]) -> Result<(), String> {
    tcp.write_all(buf).map_err(|err| format!("Failed to write bytes to external socket {:?}", err))
}
