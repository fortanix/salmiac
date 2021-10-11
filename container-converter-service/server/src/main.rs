mod operation;
mod session;

use iron::{Chain, IronResult, IronError, Request, Response};
use log::error;
use once_cell::sync::Lazy;

use webservice::server::ApiHandler;
use webservice::routes;
use webservice::routing::Route;
use webservice::api_model::define_apis;
use webservice::api_model::marker_types::Empty;
use webservice::server::{Serve, Server};
use webservice::diagnostic_logging;
use webservice::metrics::{Metrics, MetricsImpl};

use webservice::operation::{Operation, StateOf, OperationState, HasOperationState, SessionOf};
use webservice::routing::{build_router};
use webservice::post_response_logging::Log;
use senclave::http::handle_connection;
use senclave::secure_network::{create_service_pki, threads, ClientValidationStrategy};

use std::net::SocketAddr;
use std::io::Write;
use std::result::Result as StdResult;
use database::tasks::{DeferredTasksHandlerImpl, DeferredTasksHandler};
use database::Transaction;

pub const VERSION: &'static str = env!("CARGO_PKG_VERSION");

define_apis! {
//  Method & Path  => Operation name  (Input type)     -> Output type
    post "/convert" => Convert         (Empty)          -> String
}

pub fn routes() -> Vec<Route<crate::ConverterServer>> {
    routes!(
//      Name:  ( API model          => API implementation     )
        convert: ( Convert => operation::ConvertImage ),// explicitly specify the api model
    )
}

pub struct NoLog {}

impl Log for NoLog {}

pub struct ConverterServer {
    deferred_tasks_handler: DeferredTasksHandlerImpl,
    metrics: MetricsImpl,
}

impl Server for ConverterServer {
    type Ref = &'static Self;
    type Log = NoLog;
    type Interface = ();

    fn build_handler(server: Self::Ref, routes: &[Route<Self>], _: Self::Interface) -> Chain {
        let mut chain = Chain::new(build_router(server, routes));
        //chain.link_after(HandlePostResponseLogs::new(server));
        chain
    }

    fn deferred_tasks_handler(&self) -> &dyn DeferredTasksHandler {
        &self.deferred_tasks_handler
    }

    fn metrics(&self) -> &dyn Metrics {
        &self.metrics
    }

    // This method is called by the HandlePostResponseLogs middleware on operation success, for
    // operations that have the PostResponseLogs<T> output type.
    fn deferred_logs(&self, _req: &Request, _res: StdResult<&Response, &IronError>, logs: Vec<Self::Log>) {
        //self.deferred_logs(logs)
    }

}

impl<'s, A, S> Serve<'s, A, S> for ConverterServer
    where A: Operation + HasOperationState<'s, S, <A as Operation>::Out>,

{
    // Example application-specific pre_validate_input() hook
    fn pre_validate_input(&self, state: &StateOf<'s, A>) -> IronResult<()> {

        Ok(())
    }

    // Example application-specific post_check_access() hook
    fn post_check_access(&self, state: &StateOf<'s, A>) -> IronResult<()> {

        Ok(())
    }

    // This is called when any operation fails
    fn log_failed_operation(&self, e: &IronError, session: &S, _txn: &Transaction, socket: Option<SocketAddr>) {
        let socket_addr = socket.map_or("<unknown>".to_owned(), |s| s.to_string());
        error!("Operation '{}' with socket address '{}' failed with error '{}'", A::name(), socket_addr, e)
    }
}

impl Default for ConverterServer {
    fn default() -> Self {
        Self {
            deferred_tasks_handler: DeferredTasksHandlerImpl::new(),
            metrics: MetricsImpl::new(&[]),
        }
    }
}

fn build_handler() -> Chain {
    // We use a Lazy/OnceCell to store the server instance, alternatively we could store the
    // instance on the heap and use an Arc instead.
    static SERVER: Lazy<ConverterServer> = Lazy::new(|| { ConverterServer::default()});
    ConverterServer::build_handler(&*SERVER, &routes(), ())
}

fn main() {
    env_logger::init();

    let chain = build_handler();

    let server_port = 8080;
    let pki = create_service_pki("webservice-example.default.svc.cluster.local")
        .expect("failed to obtain certificate from enclave manager");

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
            handle_connection(&chain, stream.as_network_stream(), |_| {}, peer_addr, server_port)
        }
    );

    loop { std::thread::park() }

}
