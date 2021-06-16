use clap::{App, AppSettings, Arg, SubCommand, ArgMatches};

use env_logger;

use vsock_proxy::{Proxy, open_packet_capture, create_tap_device, add_tap_gateway};

use vsock_proxy::net::socket_extensions::{
    RichListener,
    RichSender
};

use std::net::{IpAddr, Ipv4Addr};
use std::process::exit;
use dns_lookup::lookup_host;
use std::str::FromStr;
use std::fmt::Display;
use std::io::{Write};

fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    match matches.subcommand() {
        ("proxy", Some(args)) => {

            let local_port  = parse_console_argument::<u32>(args, "vsock-port")?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;
            let cid         = parse_console_argument::<u32>(args, "cid")?;

            let proxy = Proxy::new(local_port, IpAddr::V4(Ipv4Addr::UNSPECIFIED), remote_port);

            let mut vsock_stream = proxy.connect_to_enclave(cid)?;

            println!("Connected to enclave!");

            let mut capture = open_packet_capture()?;
            capture.filter("port 5007");

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

            let proxy = Proxy::new(0, IpAddr::V4(Ipv4Addr::UNSPECIFIED), remote_port);

            let mut _listener = proxy.connect_remote_forget()?;

            println!("Listening remote as a test program!");

            loop {
                let reesult = _listener.accept_string()?;
                println!("Received string from tap into test program! {}", reesult);
            }
        }
        ("client", Some(args)) => {
            let address_vec = address_argument(args)?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;

            let client = Proxy::new(0, address_vec[0], remote_port);

            let mut ec2_connect = client.connect_remote_forget()?;

            println!("Connected to EC2!");

            let data = "Hello, world from client!".to_string();
            ec2_connect.send_string(data)?;

            println!("Sent string to EC2!");
        },
        ("server", Some(args)) => {
            let local_port  = parse_console_argument::<u32>(args, "vsock-port")?;

            let server = Proxy::new(local_port, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

            let mut parent_listener = server.listen_parent()?;

            println!("Listening to parent!");

            let mut tap_device = create_tap_device()?;

            println!("Created tap device!");

            add_tap_gateway()?;

            println!("Added gateway to tap");

            loop {
                let packet = parent_listener.accept_packet()?;
                println!("Accepted data from parent: {:?}", packet);

                tap_device.write_all(&packet);

                println!("Sent data to tap!");
            }
        }
        _ => {
            println!("Program must be either 'proxy' or 'client' or 'server'");
            exit(1);
        }
    }

    exit(0);
}

fn parse_console_argument<T : FromStr + Display>(args: &ArgMatches, name: &str) -> Result<T, String> {
    args.value_of(name)
        .map(|e| e.parse::<T>())
        .expect(format!("{} must be specified", name).as_str())
        .map_err(|_err| format!("Cannot parse console argument {}", name))
}

fn address_argument(args: &ArgMatches) -> Result<Vec<IpAddr>, String> {
    args.value_of("address")
        .map(|e| lookup_host(&e))
        .expect("address must be specified")
        .map_err(|err| format!("Cannot parse address {:?}", err))
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Vsock proxy")
        .about("Vsock proxy")
        .setting(AppSettings::DisableVersion)
        .subcommand(
            SubCommand::with_name("proxy")
                .about("Transfer traffic from/to enclave")
                .arg(
                    Arg::with_name("cid")
                        .long("cid")
                        .help("cid")
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
                .about("Connect to EC2")
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
                .about("Listens for incoming connections")
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
                .about("Listens for tap device")
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
