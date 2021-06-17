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
    bind_udp,
    connect_remote_tcp,
    listen_remote_tcp
};

use vsock_proxy::net::socket_extensions::{
    RichListener,
    RichSender
};

use vsock_proxy::net::create_tap_device;
use vsock_proxy::net::packet_capture::{
    open_enclave_capture,
    open_parent_capture
};
use threadpool::ThreadPool;


use std::net::{IpAddr, SocketAddr, Ipv4Addr};
use std::{
    process,
    thread,
    time
};
use std::str::FromStr;
use std::fmt::Display;
use std::io::{Write};

fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    let thread_pool = ThreadPool::new(2);

    match matches.subcommand() {
        ("proxy", Some(args)) => {

            let local_port  = parse_console_argument::<u32>(args, "vsock-port")?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;
            //let cid         = parse_console_argument::<u32>(args, "cid")?;

            let proxy = Proxy::new(local_port, 4, remote_port);

            let mut enclave_listener = proxy.listen_parent()?;

            println!("Awaiting confirmation from enclave!");
            {
                loop {
                    let acc = enclave_listener.accept_u64();

                    if acc.is_ok() && acc.unwrap() == 1 {
                        println!("Got confirmation from enclave!");
                        break;
                    }
                }
            }

            let mut enclave_stream = proxy.connect_to_enclave()?;

            println!("Connected to enclave!");

            let mut capture = open_parent_capture(remote_port as u32)?;
            let mut capture2 = open_parent_capture(remote_port as u32)?;

            println!("Listening to packets!");

            thread_pool.execute(move || {
                loop {
                    while let Ok(packet) = capture.next() {
                        println!("received packet in parent! {:?}", packet);
                        enclave_stream.send_packet(packet);
                    }
                }
            });

            thread_pool.execute(move || {
                loop {
                    let packet = match enclave_listener.accept_packet() {
                        Ok(packet) => {
                            println!("Received packet from enclave!");
                            packet
                        }
                        Err(err) => {
                            println!("Failed to accept packet from enclave: {:?}", err);
                            break;
                        }
                    };

                    println!("Accepted data from enclave: {:?}", packet);

                    capture2.sendpacket(packet);

                    println!("Sent data to interface!");
                }
            });

            loop {}
        }
        ("test", Some(args)) => {
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;

            let mut tcp_listener = listen_remote_tcp(IpAddr::V4(Ipv4Addr::UNSPECIFIED), remote_port as u32)?;
            //let mut udp_listener = bind_udp(remote_port)?;

            println!("Listening to tap device as a test client program!");

            loop {
                let result = tcp_listener.accept_string()?;
                //let result = udp_listener.accept_string()?;
                println!("Received string from tap as a test program! {}", result);
            }
        }
        ("client", Some(args)) => {
            let address_vec = address_argument(args)?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;

            let mut ec2_connect = connect_remote_tcp(address_vec[0], remote_port as u32)?;
            //let ec2_connect = bind_udp(remote_port)?;

            println!("Connected to EC2!");

            let address = SocketAddr::from((address_vec[0], remote_port));
            let message = "Hello world from outside EC2!".to_string();

            ec2_connect.send_string(message);
            //ec2_connect.send_to(message.as_bytes(), address).map_err(|err| format!("cannot send udp! {:?}", err));

            println!("Sent string to EC2!");
        },
        ("server", Some(args)) => {
            let local_port  = parse_console_argument::<u32>(args, "vsock-port")?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;

            let mut tap_device = create_tap_device()?;

            println!("Created tap device in enclave!");

            let mut packet_capture = open_enclave_capture(remote_port as u32)?;

            println!("Listening to packets in enclave!");

            let server = Proxy::new(local_port, 4, remote_port);

            let mut self_listener = server.listen_enclave()?;

            println!("Listening to self!");

            let server2 = Proxy::new(local_port, 3, remote_port);

            let mut parent_connection = server2.connect_to_enclave()?;

            println!("Connected to parent!");

            parent_connection.send_u64(1);

            thread_pool.execute(move || {
                loop {
                    let packet = match self_listener.accept_packet() {
                        Ok(packet) => {
                            packet
                        }
                        Err(err) => {
                            println!("Failed to accept packet from parent: {:?}", err);
                            break
                        }
                    };

                    println!("Accepted data from parent: {:?}", packet);

                    tap_device.write_all(&packet);

                    println!("Sent data to tap!");
                }
            });

            thread_pool.execute(move || {
                loop {
                    while let Ok(packet) = packet_capture.next() {
                        println!("Captured packet in enclave! {:?}", packet);
                        parent_connection.send_packet(packet);

                        println!("Sent packet to parent!");
                    }
                }
            });

            loop {}
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
                .arg(
                    Arg::with_name("remote-port")
                        .long("remote-port")
                        .help("remote port")
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
