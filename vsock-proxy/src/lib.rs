pub mod net;

use nix::sys::socket::{SockAddr};
use std::net::{IpAddr, SocketAddr, TcpStream, TcpListener, Ipv4Addr, UdpSocket};
use vsock::{VsockListener, VsockStream};
use pcap::{Device, Capture, Active, Error};
use tun::platform::linux::Device as TunDevice;
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys as netlink;
use netlink_packet_route::{
    NetlinkMessage,
    NetlinkHeader,
    NetlinkPayload,
    RouteMessage,
    RouteHeader
};

use netlink_packet_route::rtnl::constants;

use netlink_packet_route::rtnl::RtnlMessage;

pub const VSOCK_PROXY_CID: u32 = 3; // from AWS Nitro documentation

pub const VSOCK_ANY_CID : u32 = 0xFFFFFFFF;

pub const PARENT_NETWORK_INTERFACE : &str = "ens5";

pub fn open_packet_capture() -> Result<pcap::Capture<Active>, String> {
    fn find_device(devices: Vec<Device>) -> Result<Device, Error> {
        devices.into_iter()
            .find(|e| e.name == PARENT_NETWORK_INTERFACE)
            .ok_or(Error::PcapError(format!("Can't find {:?} device", PARENT_NETWORK_INTERFACE)))
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

    netlink_message.header.flags = constants::NLM_F_CREATE | constants::NLM_F_EXCL | constants::NLM_F_ACK;
    netlink_message.header.sequence_number = 1;
    netlink_message.finalize();

    netlink_message
}

pub fn add_tap_gateway() -> Result<usize, String> {
    let socket_result = netlink::Socket::new(NETLINK_ROUTE).map_err(|err| format!("Cannot open netlink socket {:?}", err));

    let result = socket_result.and_then(|socket| {
        let message = default_gateway_message();

        let mut buf = vec![0; message.header.length as usize];

        assert!(buf.len() == message.buffer_len());

        message.serialize(&mut buf[..]);

        let kernel_addr = netlink::SocketAddr::new(0, 0);

        socket.send_to(&buf[..], &kernel_addr, 0).map_err(|err| format!("Failed to send message via netlink {:?}", err))
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

    pub fn connect_to_enclave(&self, cid: u32) -> Result<VsockStream, String> {
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
        UdpSocket::bind("0.0.0.0:5007").map_err(|err| format!("Failed to connect to external port {:?}", err))
    }
}


