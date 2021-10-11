use webservice::session_lookup::SessionLookup;
use iron::{Request, IronResult};
use crate::ConverterServer;
use database::Transaction;

pub struct NoAuthRequired;
impl SessionLookup<ConverterServer> for NoAuthRequired {
    type Session = UnauthenticatedSession; // This session type is what is available to operations that use this SessionLookup as their Session type

    fn lookup(req: &mut Request, _txn: &Transaction, _server: &ConverterServer) -> IronResult<Self::Session> {
        Ok(UnauthenticatedSession { client_ip: req.remote_addr.ip() })
    }
}

/// Session for clients that have not been authenticated yet
pub struct UnauthenticatedSession {
    pub client_ip: std::net::IpAddr,
}
