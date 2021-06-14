use nix::sys::socket::{SockAddr};
use nix::net::if_::if_nametoindex;
use std::io;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, TcpListener, Ipv4Addr, UdpSocket};
use vsock::{VsockListener, VsockStream};
use pcap::{Device, Capture, Active, Packet, Error};
use tun::platform::linux::Device as TunDevice;
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys as netlink;
use netlink_packet_route::{
    NetlinkMessage,
    NetlinkHeader,
    NetlinkPayload,
    LinkMessage,
    AddressMessage,
    AddressHeader,
    RouteMessage,
    RouteHeader
};

use netlink_packet_route::rtnl::constants;

use netlink_packet_route::rtnl::RtnlMessage;

pub const VSOCK_PROXY_CID: u32 = 3; // from AWS Nitro documentation

pub const VSOCK_ANY_CID : u32 = 0xFFFFFFFF;

pub const PARENT_NETWORK_INTERFACE : &str = "ens5";

pub const BUF_SIZE : usize = 4096;

pub fn open_capture() -> Result<Capture<Active>, String> {
    fn find_device(devices: Vec<Device>) -> Result<Device, Error> {
        devices.into_iter()
            .find(|e| e.name == PARENT_NETWORK_INTERFACE)
            .ok_or(Error::PcapError(format!("Cant find {:?} device", PARENT_NETWORK_INTERFACE)))
    }

    let main_device = Device::list()
        .and_then(|devices|{ find_device(devices) })
        .map_err(|err| format!("Failed to create device {:?}", err));

    let capture = main_device.and_then(|device| {
        println!("Capturing with device: {}", device.name);
        Capture::from_device(device).map_err(|err| format!("Cannot create capture {:?}", err))
    });

    capture.and_then(|capture| {
        let result = capture.promisc(true)
            .immediate_mode(true)
            .snaplen(5000)
            .open();

        result.map_err(|err| format!("Cannot open capture {:?}", err))
    })
}

pub fn create_tap_device() -> Result<TunDevice, String> {
    let mut config = tun::Configuration::default();
    config.address((172,31,46,106))
        .netmask((255,255,240,0))
        .layer(tun::Layer::L2)
        .up();

    tun::create(&config).map_err(|err| format!("Cannot create tap device {:?}", err))
}

fn default_gateway_message() -> NetlinkMessage<RtnlMessage> {
    use netlink_packet_route::rtnl::route::Nla;

    let header = RouteHeader {
        address_family: constants::AF_INET as u8,
        destination_prefix_length: 32,
        source_prefix_length: 32,
        tos: 0,
        table: constants::RT_TABLE_MAIN,
        protocol: constants::RTPROT_BOOT,
        scope: constants::RT_SCOPE_UNIVERSE,
        kind: constants::RTN_UNICAST,
        flags: Default::default()
    };

    let gateway = Nla::Gateway(Ipv4Addr::new(172, 31, 32, 1).octets().to_vec());

    let message = RouteMessage {
        header,
        nlas: vec![gateway]
    };

    let mut netlink_message = NetlinkMessage {
        header: NetlinkHeader::default(),
        payload: NetlinkPayload::from(RtnlMessage::NewRoute(message)),
    };

    netlink_message.header.flags = constants::NLM_F_CREATE | constants::NLM_F_EXCL;
    netlink_message.header.sequence_number = 1;
    netlink_message.finalize();

    netlink_message
}

pub fn print_network_devices_data() -> () {
    let socket = netlink::Socket::new(NETLINK_ROUTE).expect("Cannot create netlink socket");
    let kernel_addr = netlink::SocketAddr::new(0, 0);

    let mut packet = NetlinkMessage {
        header: NetlinkHeader::default(),
        payload: NetlinkPayload::from(RtnlMessage::GetLink(LinkMessage::default())),
    };

    packet.header.flags = constants::NLM_F_DUMP | constants::NLM_F_REQUEST;
    packet.header.sequence_number = 1;
    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];

    // Before calling serialize, it is important to check that the buffer in which we're emitting is big
    // enough for the packet, other `serialize()` panics.
    assert!(buf.len() == packet.buffer_len());
    packet.serialize(&mut buf[..]);

    socket.send(&buf[..], 0).unwrap();

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;

    // we set the NLM_F_DUMP flag so we expect a multipart rx_packet in response.
    loop {
        let size = socket.recv(&mut receive_buffer[..], 0).unwrap();

        loop {
            let bytes = &receive_buffer[offset..];
            // Note that we're parsing a NetlinkBuffer<&&[u8]>, NOT a NetlinkBuffer<&[u8]> here.
            // This is important because Parseable<NetlinkMessage> is only implemented for
            // NetlinkBuffer<&'a T>, where T implements AsRef<[u8] + 'a. This is not
            // particularly user friendly, but this is a low level library anyway.
            //
            // Note also that the same could be written more explicitely with:
            //
            // let rx_packet =
            //     <NetlinkBuffer<_> as Parseable<NetlinkMessage>>::parse(NetlinkBuffer::new(&bytes))
            //         .unwrap();
            //
            let rx_packet: NetlinkMessage<RtnlMessage> =
                NetlinkMessage::deserialize(bytes).unwrap();

            println!("NETLINK PACKET {:?}", rx_packet);

            if rx_packet.payload == NetlinkPayload::Done {
                println!("Done!");
                return;
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }
}

pub fn add_tap_gateway() -> Result<usize, String> {
    let socket_result = netlink::Socket::new(NETLINK_ROUTE).map_err(|err| format!("Cannot open netlink socket {:?}", err));

    let result = socket_result.and_then(|socket| {
        let message = default_gateway_message();

        let mut buf = vec![0; message.header.length as usize];

        assert!(buf.len() == message.buffer_len());

        message.serialize(&mut buf[..]);

        socket.send(&buf[..], 0).map_err(|err| format!("Failed to send message via netlink {:?}", err))
    });

    result
}

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

    pub fn listen_parent(&self) -> Result<VsockListener, String> {
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

    pub fn connect_remote_forget(&self) -> Result<UdpSocket, String> {
        UdpSocket::bind("52.51.191.94:5007").map_err(|err| format!("Failed to connect to external port {:?}", err))
    }

    pub fn listen_remote_forget(&self) -> Result<UdpSocket, String> {
        UdpSocket::bind("0.0.0.0:5007").map_err(|err| format!("Failed to connect to external port {:?}", err))
    }
}

pub fn accept_packet(vsock : &mut VsockListener) -> Result<Vec<u8>, String> {
    loop {
        let (mut incoming, _) = vsock.accept().map_err(|err| format!("Accept from enclave socket failed: {:?}", err))?;

        return receive_packet(&mut incoming)
    }
}

pub fn get_connection(vsock : &mut VsockListener) -> Result<VsockStream, String> {
    loop {
        let (mut incoming, _) = vsock.accept().map_err(|err| format!("Accept from enclave socket failed: {:?}", err))?;

        return Ok(incoming)
    }
}

pub fn accept_packets(vsock : &mut VsockListener) -> Result<(), String> {
    let mut incoming = get_connection(vsock)?;

    loop {
        let packet = receive_packet(&mut incoming);
        println!("Accepted data from parent: {:?}", packet);
    }
}

pub fn send_packet(device : &mut dyn Write, packet : Packet) -> Result<(), String> {
    let send_length = send_u64(device, packet.header.caplen as u64)
        .map_err(|err| format!("Failure to send captured packet to vsock: {:?}", err));

    send_length.and_then(|_| {
        send_bytes0(device, packet.data).map_err(|err| format!("Failure to send captured packet to vsock: {:?}", err))
    })
}

pub fn receive_packet(incoming: &mut dyn Read) -> Result<Vec<u8>, String> {
    let mut buf = [0u8; BUF_SIZE];
    let len = receive_u64(incoming).map_err(|err| format!("Failed to receive packet len {:?}", err));

    let packet_raw = len.and_then(|len| {
        println!("Received packet len of {}", len);
        receive_bytes0(incoming, &mut buf, len).map(|_| len as usize)
    }).map_err(|err| format!("Failed to receive packet {:?}", err));

    return packet_raw.map(|len| buf[0..len].to_vec());
}

pub fn accept_string(listener : &mut VsockListener) -> Result<String, String> {
    loop {
        let (mut incoming, _) = listener.accept().map_err(|err| format!("Accept from enclave socket failed: {:?}", err))?;

        return receive_string(&mut incoming);
    }
}

pub fn accept_string1(listener : &mut TcpListener) -> Result<String, String> {
    loop {
        let (mut incoming, _) = listener.accept().map_err(|err| format!("Accept from enclave socket failed: {:?}", err))?;

        return receive_string(&mut incoming);
    }
}

pub fn send_string(tcp: &mut dyn Write, data : String) -> Result<(), String> {
    let buf = data.as_bytes();
    let len = buf.len() as u64;

    send_u64(tcp, len).and_then(|_e| send_bytes0(tcp, &buf))
}

pub fn receive_string(tcp :&mut dyn Read) -> Result<String, String> {
    let len = receive_u64(tcp)?;
    let mut buf = [0u8; BUF_SIZE];
    receive_bytes0(tcp, &mut buf, len)?;

    let received = String::from_utf8(buf.to_vec()).map_err(|err| format!("The received bytes are not UTF-8: {:?}", err));

    received
}

fn receive_bytes0(tcp: &mut dyn Read, buf: &mut [u8], len: u64) -> Result<(), String> {
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

    receive_bytes0(tcp, &mut buf, size).map(|_e| LittleEndian::read_u64(&buf))
}

fn send_u64(tcp: &mut dyn Write, val: u64) -> Result<(), String> {
    use std::mem::size_of;
    use byteorder::LittleEndian;
    use byteorder::ByteOrder;

    let mut buf = [0u8; size_of::<u64>()];
    LittleEndian::write_u64(&mut buf, val);

    send_bytes0(tcp, &mut buf)
}

fn send_bytes0(tcp: &mut dyn Write, buf: &[u8]) -> Result<(), String> {
    tcp.write_all(buf).map_err(|err| format!("Failed to write bytes to external socket {:?}", err))
}
