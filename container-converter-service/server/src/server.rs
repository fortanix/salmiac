use std::net::SocketAddr;
use std::result::Result as StdResult;

use webservice::routing::Route;
use webservice::server::{Serve, Server};
use webservice::metrics::{Metrics, MetricsImpl};
use webservice::operation::{Operation, HasOperationState};
use webservice::routing::{build_router};
use database::tasks::{DeferredTasksHandlerImpl, DeferredTasksHandler};
use database::Transaction;

use iron::{Chain, IronError, Request, Response};
use log::error;
use tokio::runtime::Runtime;

pub struct ConverterServer {
    deferred_tasks_handler: DeferredTasksHandlerImpl,
    metrics: MetricsImpl,
    tokio: Runtime
}

impl ConverterServer {
    pub fn tokio(&self) -> &Runtime {
        &self.tokio
    }
}

impl Server for ConverterServer {
    type Ref = &'static Self;
    type Log = ();
    type Interface = ();

    fn build_handler(server: Self::Ref, routes: &[Route<Self>], _: Self::Interface) -> Chain {
        let chain = Chain::new(build_router(server, routes));
        chain
    }

    fn deferred_tasks_handler(&self) -> &dyn DeferredTasksHandler {
        &self.deferred_tasks_handler
    }

    fn metrics(&self) -> &dyn Metrics {
        &self.metrics
    }

    fn deferred_logs(&self, _req: &Request, _res: StdResult<&Response, &IronError>, logs: Vec<Self::Log>) {
    }

}

impl<'s, A, S> Serve<'s, A, S> for ConverterServer
    where A: Operation + HasOperationState<'s, S, <A as Operation>::Out>,

{
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
            tokio: Runtime::new().expect("Failed to create tokio runtime"),
        }
    }
}