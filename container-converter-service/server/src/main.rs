mod operation;
mod server;

use std::io::Write;
use std::path::Path;
use std::fs;

use webservice::routes;
use webservice::routing::Route;
use webservice::api_model::define_apis;
use webservice::server::{Server};
use senclave::http::handle_connection;
use senclave::secure_network::{threads, ClientValidationStrategy, PKI};
use container_converter::ConverterArgs;

use crate::server::ConverterServer;

use once_cell::sync::Lazy;
use clap::{ArgMatches, AppSettings, App, Arg};
use iron::Chain;

define_apis! {
//  Method & Path  => Operation name  (Input type)     -> Output type
    post "/convert" => Convert         (ConverterArgs) -> String
}

pub fn routes() -> Vec<Route<crate::ConverterServer>> {
    routes!(
//      Name:  ( API model          => API implementation     )
        convert: ( Convert => operation::ConvertImage ),
    )
}

fn main() -> Result<(), String> {
    database::cache::CACHE.set(database::cache::CacheBuilder::new().build())
        .expect("Failed to set cache");

    let console_arguments = console_arguments();

    let server_port = console_arguments.value_of("port")
        .map(|e| u16::from_str_radix(e, 10))
        .expect("Failed to parse port")
        .expect("Port argument must be specified");

    let certificate_path = console_arguments.value_of("certificate-file")
        .map(|e| Path::new(e))
        .expect("Certificate path is required");

    let key_path = console_arguments.value_of("key-file")
        .map(|e| Path::new(e))
        .expect("Key path is required");

    let certificate = fs::read_to_string(certificate_path)
        .map_err(|e| format!("Failed to read certificate file. {:?}", e))?;

    let key = fs::read_to_string(key_path)
        .map_err(|e| format!("Failed to read key file. {:?}", e))?;

    let pki = PKI::new_pki_from_vecs(certificate.as_bytes(), key.as_bytes())
        .expect(&format!("Failed to create PKI from certificate {} and key {}",
                         certificate_path.display(),
                         key_path.display()));

    let handler = build_handler();
    threads::run_public_server::<fn(Option<&[u8]>) -> bool, _>(
        server_port,
        vec![pki],
        ClientValidationStrategy::None,
        move |mut stream| {
            // Make sure TLS connection is established
            if stream.flush().is_err() {
                return
            }

            let peer_addr = stream.peer_addr();
            handle_connection(&handler,
                              stream.as_network_stream(),
                              |_| {},
                              peer_addr,
                              server_port)
        }
    );

    loop { std::thread::park() }
}

fn build_handler() -> Chain {
    static SERVER: Lazy<ConverterServer> = Lazy::new(|| { ConverterServer::default()});
    ConverterServer::build_handler(&*SERVER, &routes(), ())
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Container converter web service")
        .about("REST Api for container converter")
        .setting(AppSettings::DisableVersion)
        .arg(
            Arg::with_name("port")
                .help("http port")
                .long("port")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("certificate-file")
                .help("Path to certificate file")
                .long("certificate-file")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("key-file")
                .help("Path to a key file")
                .long("key-file")
                .takes_value(true)
                .required(true),
        )
        .get_matches()
}