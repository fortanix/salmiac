use clap::{
    App,
    AppSettings,
    Arg,
    SubCommand,
    ArgMatches
};

use env_logger;

use vsock_proxy::{
    Proxy,
    bind_udp
};

use vsock_proxy::net::socket_extensions::{
    RichListener,
    RichSender
};

use vsock_proxy::net::create_tap_device;

use std::net::{
    IpAddr,
    SocketAddr
};
use std::process;
use std::str::FromStr;
use std::fmt::Display;
use std::io::{Write};

const VSOCK_ANY_CID : u32 = 0xFFFFFFFF;

fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    match matches.subcommand() {
        ("proxy", Some(args)) => {

            let local_port  = parse_console_argument::<u32>(args, "vsock-port")?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;
            let cid         = parse_console_argument::<u32>(args, "cid")?;

            let proxy = Proxy::new(local_port, cid, remote_port);

            let mut vsock_stream = proxy.connect_to_enclave()?;

            println!("Connected to enclave!");

            let mut capture = proxy.open_packet_capture()?;

            println!("Listening to packets!");
            loop {
                while let Ok(packet) = capture.next() {
                    println!("received packet! {:?}", packet);
                    vsock_stream.send_packet(packet);
                }
            }
        }
        ("test", Some(args)) => {
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;

            let mut udp_listener = bind_udp(remote_port)?;

            println!("Listening to tap device as a test client program!");

            loop {
                let result = udp_listener.accept_string()?;
                println!("Received string from tap as a test program! {}", result);
            }
        }
        ("client", Some(args)) => {
            let address_vec = address_argument(args)?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;

            let ec2_connect = bind_udp(remote_port)?;

            println!("Connected to EC2!");

            let address = SocketAddr::from((address_vec[0], remote_port));
            let message = "Hello world from outside EC2!".to_string();

            ec2_connect.send_to(message.as_bytes(), address).map_err(|err| format!("cannot send udp! {:?}", err));

            println!("Sent string to EC2!");
        },
        ("server", Some(args)) => {
            let local_port  = parse_console_argument::<u32>(args, "vsock-port")?;

            let server = Proxy::new(local_port, VSOCK_ANY_CID, 0);

            let mut parent_listener = server.listen_parent()?;

            println!("Listening to parent!");

            let mut tap_device = create_tap_device()?;

            println!("Created tap device!");

            loop {
                let packet = parent_listener.accept_packet()?;
                println!("Accepted data from parent: {:?}", packet);

                tap_device.write_all(&packet);

                println!("Sent data to tap!");
            }
        }
        _ => {
            println!("Program must be either 'proxy', 'client', 'server' or 'test'");
            process::exit(1);
        }
    }

    process::exit(0);
}

fn parse_console_argument<T : FromStr + Display>(args: &ArgMatches, name: &str) -> Result<T, String> {
    args.value_of(name)
        .map(|e| e.parse::<T>())
        .expect(format!("{} must be specified", name).as_str())
        .map_err(|_err| format!("Cannot parse console argument {}", name))
}

fn address_argument(args: &ArgMatches) -> Result<Vec<IpAddr>, String> {
    args.value_of("address")
        .map(|e| dns_lookup::lookup_host(&e))
        .expect("address must be specified")
        .map_err(|err| format!("Cannot parse address {:?}", err))
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Vsock proxy")
        .about("Vsock proxy")
        .setting(AppSettings::DisableVersion)
        .subcommand(
            SubCommand::with_name("proxy")
                .about("Vsock proxy that runs inside the parent")
                .arg(
                    Arg::with_name("cid")
                        .long("cid")
                        .help("cid (enclave id)")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("vsock-port")
                        .long("vsock-port")
                        .help("vsock port")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("remote-port")
                        .long("remote-port")
                        .help("remote port")
                        .takes_value(true)
                        .required(true),
                )
        )
        .subcommand(
            SubCommand::with_name("client")
                .about("Client that sends messages to to EC2")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .help("EC2 address")
                        .takes_value(true)
                        .required(true),
                )
                .arg(
                    Arg::with_name("remote-port")
                        .long("remote-port")
                        .help("remote port")
                        .takes_value(true)
                        .required(true),
                )
        )
        .subcommand(
            SubCommand::with_name("server")
                .about("Vsock-proxy that runs inside the enclave")
                .arg(
                    Arg::with_name("vsock-port")
                        .long("vsock-port")
                        .help("vsock port")
                        .takes_value(true)
                        .required(true),
                )
        )
        .subcommand(
            SubCommand::with_name("test")
                .about("Test program that represents the client running inside the enclave")
                .arg(
                    Arg::with_name("remote-port")
                        .long("remote-port")
                        .help("remote port")
                        .takes_value(true)
                        .required(true),
                )
        )
        .get_matches()
}
