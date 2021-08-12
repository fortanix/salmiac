use env_logger;
use vsock_proxy::{
    bind_udp,
    connect_remote_tcp,
    listen_remote_tcp
};
use vsock_proxy::net::socket::{RichSocket, RichUdp};
use vsock_proxy::mode;
use threadpool::ThreadPool;

use std::net::{IpAddr, SocketAddr, Ipv4Addr};
use std::{
    process,
};
use std::env;
use log::{
    info,
    debug,
    error
};
use vsock_proxy::mode::{
    parse_console_argument,
    console_arguments,
    address_argument
};

fn main() -> Result<(), String> {
    env::set_var("RUST_LOG","debug");

    env_logger::init();

    let matches = console_arguments();

    match matches.subcommand() {
        ("parent", Some(args)) => {

            let local_port  = parse_console_argument::<u32>(args, "vsock-port")?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;
            let thread_pool = ThreadPool::new(2);

            mode::parent::run(local_port, remote_port, thread_pool)?;
        }
        ("enclave", Some(args)) => {
            let local_port  = parse_console_argument::<u32>(args, "vsock-port")?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;
            let thread_pool = ThreadPool::new(2);

            mode::enclave::run(local_port, remote_port, thread_pool)?;
        }
        ("test", Some(args)) => {
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;

            if args.is_present("udp") {
                let mut udp_listener = RichUdp(bind_udp(remote_port)?);

                loop {
                    let result : String = udp_listener.receive()?;

                    info!("Received string from tap as a test program! {}", result);
                }
            }
            else {
                let tcp_listener = listen_remote_tcp(IpAddr::V4(Ipv4Addr::UNSPECIFIED), remote_port as u32)?;

                info!("Listening to tap device as a test client program!");

                loop {
                    let mut incoming = tcp_listener.accept()
                        .map(|r| r.0)
                        .map_err(|err| format!("Accept from enclave socket failed: {:?}", err))?;

                    debug!("Accepted TCP connection outside EC!");


                    let result : String = incoming.receive()?;

                    info!("Received string from tap as a test program! {}", result);
                }
            }
        }
        ("client", Some(args)) => {
            let address = address_argument(args)?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;

            let message = "Hello world from outside EC2!".to_string();

            if args.is_present("udp") {
                let ec2_connect = bind_udp(remote_port)?;
                let address = SocketAddr::from((address, remote_port));

                ec2_connect.send_to(message.as_bytes(), address).map_err(|err| format!("cannot send udp! {:?}", err))?;
            }
            else {
                let mut ec2_connect = connect_remote_tcp(address, remote_port as u32)?;

                info!("Connected to EC2!");

                ec2_connect.send(message)?;
            }

            info!("Sent string to EC2!");
        }
        _ => {
            error!("Program must be either 'proxy', 'client', 'server' or 'test'");
            process::exit(1);
        }
    }

    process::exit(0);
}
