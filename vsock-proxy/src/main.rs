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
use vsock_proxy::net::packet_capture::{
    open_enclave_capture,
    open_parent_capture
};
use threadpool::ThreadPool;


use std::net::{IpAddr, SocketAddr, Ipv4Addr};
use std::{
    process,
    sync
};
use std::str::FromStr;
use std::fmt::Display;
use std::io::{Write, Read};
use vsock::VsockStream;
use tun::platform::linux::Device;
use pcap::{Capture, Active};

fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    match matches.subcommand() {
        ("proxy", Some(args)) => {

            let local_port  = parse_console_argument::<u32>(args, "vsock-port")?;
            let remote_port = parse_console_argument::<u16>(args, "remote-port")?;
            let thread_pool = ThreadPool::new(2);

            run_proxy(local_port, remote_port, thread_pool);
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
            let thread_pool = ThreadPool::new(2);

            run_server(local_port, remote_port, thread_pool);
        }
        _ => {
            println!("Program must be either 'proxy', 'client', 'server' or 'test'");
            process::exit(1);
        }
    }

    process::exit(0);
}

fn await_confirmation_from_enclave(from_enclave : &mut VsockStream) -> Result<(), String> {
    loop {
        let acc = from_enclave.accept_u64()?;

        if acc == 1 {
            return Ok(());
        }
    }
}

fn read_from_device(mut capture : Capture<Active>, mut enclave_stream : VsockStream) -> Result<(), String> {
    loop {
        {
            /*println!("TRY device read lock!");

            let mut capture = capture_lock.lock().map_err(|err| format!("Failed to acquire pcap lock {:?}", err))?;

            println!("acquired device read lock!");*/

            let packet = capture.next().map_err(|err| format!("Failed to read packet from pcap {:?}", err))?;

            println!("Captured packet from network device in parent! {:?}", packet);

            enclave_stream.send_packet(packet.data)?;

            println!("Sent network packet to enclave!");

            /*match capture.next().map_err(|err| format!("Failed to read packet from pcap {:?}", err)) {
                Ok(packet) => {

                }
                _ => {}
            }*/
        }
    }

    Ok(())
}

fn write_to_device(mut capture : Capture<Active>, mut from_enclave : VsockStream) -> Result<(), String> {
    loop {
        let packet  = from_enclave.accept_packet().map_err(|err| format!("Failed to read packet from enclave {:?}", err))?;

        println!("Received packet from enclave! {:?}", packet);

        {
            /*println!("TRY device write lock!");

            let mut capture = capture_lock.lock().map_err(|err| format!("Failed to acquire pcap lock {:?}", err))?;

            println!("acquired device write lock!");*/

            capture.sendpacket(packet).map_err(|err| format!("Failed to send packet to device {:?}", err))?;

            println!("Sent raw packet to network device!");
        }
    }

    Ok(())
}

fn run_proxy(local_port : u32, remote_port : u16, thread_pool : ThreadPool) -> Result<(), String> {
    let proxy = Proxy::new(local_port, 4, remote_port);

    let mut enclave_listener = proxy.listen_parent()?;

    println!("Awaiting confirmation from enclave id = {}!", proxy.cid);

    let mut from_enclave = accept_vsock(&mut enclave_listener)?;

    await_confirmation_from_enclave(&mut from_enclave);

    println!("Got confirmation from enclave id = {}!", proxy.cid);

    let mut to_enclave = proxy.connect_to_enclave()?;

    println!("Connected to enclave id = {}!", proxy.cid);

    let mut capture = open_parent_capture(remote_port as u32)?;
    let mut write_capture = open_parent_capture(remote_port as u32)?;

    println!("Listening to packets from network device!");

    /*let sync_capture = sync::Arc::new(sync::Mutex::new(capture));
    let capture_read = sync_capture.clone();
    let capture_write = sync_capture.clone();*/

    thread_pool.execute(move || {
        read_from_device(capture, to_enclave);
    });

    thread_pool.execute(move || {
        write_to_device(write_capture, from_enclave);
    });

    loop {}

    Ok(())
}

fn run_server(local_port : u32, remote_port : u16, thread_pool : ThreadPool) -> Result<(), String> {
    let mut tap_device = create_tap_device()?;

    println!("Created tap device in enclave!");

    //let mut packet_capture = open_enclave_capture(remote_port as u32)?;

    //println!("Listening to packets in enclave!");

    let server = Proxy::new(local_port, 4, remote_port);

    let mut to_parent = server.connect_to_parent()?;

    println!("Connected to parent!");

    // send 'enclave ready' messsage
    to_parent.send_u64(1);

    let mut self_listener = server.listen_enclave()?;

    println!("Listening to self!");

    let mut from_parent = accept_vsock(&mut self_listener)?;

    let sync_tap = sync::Arc::new(sync::Mutex::new(tap_device));

    let tap_write = sync_tap.clone();
    let tap_read = sync_tap.clone();

    thread_pool.execute(move || {
        read_from_tap(tap_read, to_parent);
    });

    thread_pool.execute(move || {
        write_to_tap(tap_write, from_parent);
    });

    loop {}

    Ok(())
}

fn write_to_tap(tap_lock : sync::Arc<sync::Mutex<Device>>, mut from_parent : VsockStream) -> Result<(), String> {
    loop {
        let packet = from_parent.accept_packet()?;

        println!("Received packet from parent! {:?}", packet);
        {
            let mut tap_device = tap_lock.lock().map_err(|err| format!("Cannot acquire tap lock {:?}", err))?;

            println!("acquired tap write lock!");

            tap_device.write_all(&packet).map_err(|err| format!("Cannot write to tap {:?}", err))?;

            println!("Sent data to tap!");
        }
    }
}

fn read_from_tap(tap_lock : sync::Arc<sync::Mutex<Device>>, mut parent_connection : VsockStream) -> Result<(), String> {
    loop {
        let mut buf = [0u8;4096];
        {
            let mut tap_device = tap_lock.lock().map_err(|err| format!("Cannot acquire tap lock {:?}", err))?;

            println!("acquired tap read lock!");

            let amount = tap_device.read(&mut buf).map_err(|err| format!("Cannot read from tap {:?}", err))?;

            let packet = &buf[0..amount];

            println!("Read packet from tap! {:?}", packet);

            parent_connection.send_packet(packet)?;

            println!("Sent packet to parent!");
        }
    }
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
