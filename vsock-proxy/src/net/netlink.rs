use std::net::Ipv4Addr;

use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys as netlink;
use netlink_packet_route::{
    NetlinkMessage,
    NetlinkHeader,
    NetlinkPayload,
    RouteMessage,
    RouteHeader
};

use netlink_packet_route::rtnl::{
    constants,
    RtnlMessage
};

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