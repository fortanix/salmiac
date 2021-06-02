use clap::{App, AppSettings, Arg, SubCommand, ArgMatches};

use env_logger;
use log::info;
//use std::env;

use vsock_proxy::{
    Proxy,
    transfer_to_enclave,
    send_string
};

use std::net::{IpAddr, Ipv4Addr};
use std::process::exit;
use dns_lookup::lookup_host;

fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    match matches.subcommand() {
        ("proxy", Some(args)) => {
            let local_port = args
                .value_of("vsock-port")
                .map(|e| e.parse::<u32>())
                .expect("vsock-port must be specified")
                .map_err(|err| format!("Cannot parse int {:?}", err))?;

            let remote_port = args
                .value_of("remote-port")
                .map(|e| e.parse::<u16>())
                .expect("remote-port must be specified")
                .map_err(|err| format!("Cannot parse int {:?}", err))?;

            let cid = args
                .value_of("cid")
                .map(|e| e.parse::<u32>())
                .expect("cid must be specified")
                .map_err(|err| format!("Cannot parse int {:?}", err))?;

            let proxy = Proxy::new_simple(local_port, IpAddr::V4(Ipv4Addr::UNSPECIFIED), remote_port);

            let mut vsock_stream = proxy.connect_enclave(cid)?;

            info!("Connected to enclave!");

            let mut remote_listener = proxy.listen_remote()?;

            info!("Listening to external socket!");

            transfer_to_enclave(&mut vsock_stream, &mut remote_listener)?;
        }
        ("client", Some(args)) => {
            let address_vec = args
                .value_of("address")
                .map(|e| lookup_host(&e))
                .expect("address must be specified")
                .map_err(|err| format!("Cannot parse address {:?}", err))?;

            let remote_port = args
                .value_of("remote-port")
                .map(|e| e.parse::<u16>())
                .expect("remote-port must be specified")
                .map_err(|err| format!("Cannot parse int {:?}", err))?;

            let client = Proxy::new_simple(0, address_vec[0], remote_port);

            let mut ec2_connect = client.connect_remote()?;

            info!("Connected to EC2!");

            let data = "Hello, world from client!".to_string();
            send_string(&mut ec2_connect, data)?;
        }
        (_, _) => {
            info!("Program must be either 'proxy' or 'client'");
            exit(1);
        }
    }

    exit(0);
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Vsock proxy")
        .about("Vsock proxy")
        .setting(AppSettings::DisableVersion)
        .subcommand(
            SubCommand::with_name("proxy")
                .about("Transfer traffic from/to enclave")
                .arg(
                    Arg::with_name("remote-port")
                        .long("remote-port")
                        .help("remote port")
                        .takes_value(true)
                        .required(true),
                )
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
        .get_matches()
}
