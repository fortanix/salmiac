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
    RichSender,
    accept_vsock
};
use vsock_proxy::net::create_tap_device;
use threadpool::ThreadPool;

use std::net::{IpAddr, SocketAddr, Ipv4Addr};
use std::{
    process,
    sync,
    thread
};
use std::str::FromStr;
use std::fmt::Display;
use std::io::{Write, Read};
use std::env;
use log::{
    info,
    debug,
    error
};
use vsock::VsockStream;
use tun::platform::linux::Device;
use pcap::{Capture, Active};

fn main() -> Result<(), String> {
    env::set_var("RUST_LOG","debug");

    env_logger::init();

    let matches = console_arguments();

    match matches.subcommand() {
        ("proxy", Some(args)) => {

            let local_port  = parse_console_argument::<u32>(args, "vsock-port")?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;
            let thread_pool = ThreadPool::new(2);

            run_proxy(local_port, remote_port, thread_pool)?;
        }
        ("test", Some(args)) => {
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;

            if args.is_present("udp") {
                let mut udp_listener = bind_udp(remote_port)?;

                loop {
                    let result = udp_listener.receive_string()?;

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

                    let result = incoming.receive_string()?;

                    info!("Received string from tap as a test program! {}", result);
                }
            }
        }
        ("client", Some(args)) => {
            let address_vec = address_argument(args)?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;

            let message = "Hello world from outside EC2!".to_string();

            if args.is_present("udp") {
                let ec2_connect = bind_udp(remote_port)?;
                let address = SocketAddr::from((address_vec[0], remote_port));

                ec2_connect.send_to(message.as_bytes(), address).map_err(|err| format!("cannot send udp! {:?}", err))?;
            }
            else {
                let mut ec2_connect = connect_remote_tcp(address_vec[0], remote_port as u32)?;

                info!("Connected to EC2!");

                ec2_connect.send_string(message)?;
            }

            info!("Sent string to EC2!");
        },
        ("server", Some(args)) => {
            let local_port  = parse_console_argument::<u32>(args, "vsock-port")?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;
            let thread_pool = ThreadPool::new(2);

            run_server(local_port, remote_port, thread_pool)?;
        }
        _ => {
            error!("Program must be either 'proxy', 'client', 'server' or 'test'");
            process::exit(1);
        }
    }

    process::exit(0);
}

fn await_confirmation_from_enclave(from_enclave : &mut VsockStream) -> Result<(), String> {
    loop {
        let acc = from_enclave.receive_u64()?;

        if acc == 1 {
            return Ok(());
        }
    }
}

fn read_from_device(capture: &mut Capture<Active>, enclave_stream: &mut VsockStream) -> Result<(), String> {
    let packet = capture.next().map_err(|err| format!("Failed to read packet from pcap {:?}", err))?;

    debug!("Captured packet from network device in parent! {:?}", packet);

    enclave_stream.send_packet(packet.data)?;

    debug!("Sent network packet to enclave!");


    Ok(())
}

fn write_to_device(capture: &mut Capture<Active>, from_enclave: &mut VsockStream) -> Result<(), String> {
    let packet = from_enclave.receive_packet().map_err(|err| format!("Failed to read packet from enclave {:?}", err))?;

    debug!("Received packet from enclave! {:?}", packet);

    capture.sendpacket(packet).map_err(|err| format!("Failed to send packet to device {:?}", err))?;

    debug!("Sent raw packet to network device!");

    Ok(())
}

fn run_proxy(local_port : u32, remote_port : u16, thread_pool : ThreadPool) -> Result<(), String> {
    // for simplicity sake we work only with one enclave with id = 4
    let proxy = Proxy::new(local_port, 4, remote_port);

    let mut enclave_listener = proxy.listen_parent()?;

    info!("Awaiting confirmation from enclave id = {}!", proxy.cid);

    let mut from_enclave = accept_vsock(&mut enclave_listener)?;

    await_confirmation_from_enclave(&mut from_enclave)?;

    info!("Got confirmation from enclave id = {}!", proxy.cid);

    let mut to_enclave = proxy.connect_to_enclave()?;

    info!("Connected to enclave id = {}!", proxy.cid);

    // const PARENT_NETWORK_DEVICE: &str = "eth0"; // default docker device
    const PARENT_NETWORK_DEVICE: &str = "ens5"; // default EC2 device

    // `capture` should be properly locked when shared among threads (like tap device),
    // however copying captures is good enough for prototype and it just works.
    let mut capture = proxy.open_packet_capture(PARENT_NETWORK_DEVICE)?;
    let mut write_capture = proxy.open_packet_capture(PARENT_NETWORK_DEVICE)?;

    debug!("Listening to packets from network device!");

    thread_pool.execute(move || {
        loop {
            match read_from_device(&mut capture, &mut to_enclave) {
                Err(e) => {
                    error!("Failure reading from network device {:?}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    thread_pool.execute(move || {
        loop {
            match write_to_device(&mut write_capture, &mut from_enclave) {
                Err(e) => {
                    error!("Failure writing to network device {:?}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    thread_pool.join();

    Ok(())
}

fn run_server(local_port : u32, remote_port : u16, thread_pool : ThreadPool) -> Result<(), String> {
    let tap_device = create_tap_device()?;
    tap_device.set_nonblock().map_err(|_err| "Cannot set nonblock".to_string())?;

    debug!("Created tap device in enclave!");

    let server = Proxy::new(local_port, 4, remote_port);

    let mut to_parent = server.connect_to_parent()?;

    info!("Connected to parent!");

    // send 'enclave ready' messsage
    to_parent.send_u64(1)?;

    let mut self_listener = server.listen_enclave()?;

    debug!("Listening to self!");

    let mut from_parent = accept_vsock(&mut self_listener)?;

    let sync_tap = sync::Arc::new(sync::Mutex::new(tap_device));

    let tap_write = sync_tap.clone();
    let tap_read = sync_tap.clone();

    thread_pool.execute(move || {
        loop {
            let read = read_from_tap(&tap_read, &mut to_parent);


            match read {
                Ok(0) => {
                    thread::sleep_ms(5000); // if nothing was read then wait some time for packet
                }
                Err(e) => {
                    error!("Failure reading from tap device {:?}", e);
                    break;
                }
                _ => { }
            }
        }
    });

    thread_pool.execute(move || {
        loop {
            match write_to_tap(&tap_write, &mut from_parent) {
                Err(e) => {
                    error!("Failure reading from tap device {:?}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    thread_pool.join();

    Ok(())
}

fn write_to_tap(tap_lock: &sync::Arc<sync::Mutex<Device>>, from_parent: &mut VsockStream) -> Result<(), String> {
    let packet = from_parent.receive_packet()?;

    debug!("Received packet from parent! {:?}", packet);

    let mut tap_device = tap_lock.lock().map_err(|err| format!("Cannot acquire tap lock {:?}", err))?;

    debug!("acquired tap write lock!");

    tap_device.write_all(&packet).map_err(|err| format!("Cannot write to tap {:?}", err))?;

    debug!("Sent data to tap!");

    Ok(())
}

fn read_from_tap(tap_lock: &sync::Arc<sync::Mutex<Device>>, parent_connection: &mut VsockStream) -> Result<usize, String> {
    let mut buf = [0u8; 4096];

    let mut tap_device = tap_lock.lock().map_err(|err| format!("Cannot acquire tap lock {:?}", err))?;

    debug!("acquired tap read lock!");

    let amount = match tap_device.read(&mut buf).map_err(|err| format!("Cannot read from tap {:?}", err)) {
        Ok(amount) => {
            amount
        }
        Err(_) => {
            return Ok(0)
        }
    };

    let packet = &buf[0..amount];

    debug!("Read packet from tap! {:?}", packet);

    parent_connection.send_packet(packet)?;

    debug!("Sent packet to parent!");

    Ok(1)
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
                .arg(
                    Arg::with_name("udp")
                        .help("protocol name")
                        .takes_value(false)
                        .required(false),
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
                .arg(
                    Arg::with_name("udp")
                        .help("protocol name")
                        .takes_value(false)
                        .required(false),
                )
        )
        .get_matches()
}
