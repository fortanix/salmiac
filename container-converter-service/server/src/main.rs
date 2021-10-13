mod operation;
mod server;

use std::io::Write;

use webservice::routes;
use webservice::routing::Route;
use webservice::api_model::define_apis;
use webservice::server::{Server};
use senclave::http::handle_connection;
use senclave::secure_network::{create_service_pki, threads, ClientValidationStrategy};
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

    let pki = create_service_pki("webservice-example.default.svc.cluster.local")
        .expect("failed to obtain certificate from enclave manager");

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
    // We use a Lazy/OnceCell to store the server instance, alternatively we could store the
    // instance on the heap and use an Arc instead.
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
        .get_matches()
}