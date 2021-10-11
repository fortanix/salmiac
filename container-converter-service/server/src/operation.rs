
use iron::IronResult;
use webservice::with_logs;
use webservice::input::Empty;
use webservice::output::HtmlOutput;
use webservice::define_api;
use crate::ConverterServer;
use crate::session::NoAuthRequired;
use crate::Convert;

macro_rules! define_api {
    { $($operation_def:tt)* } => {
        webservice::define_api_ex! {
            (top_level_ext, operation_ext, operation_state_ext)
            $($operation_def)*
        }
    };
}

macro_rules! top_level_ext {
    (MyCustomTag, $api_model:ty, $api_impl:ty, $api_state:ty) => {
        impl $crate::operation::MyCustomTagApiMarker for $api_impl {}
    };
    ($other:ident, $api_model:ty, $api_impl:ty, $api_state:ty) => {
        webservice::top_level_ext!($other, $api_model, $api_impl, $api_state);
    };
}

macro_rules! operation_ext {
    (MyCustomTag) => {};
    ($other:ident) => {
        webservice::operation_ext!($other);
    };
}

macro_rules! operation_state_ext {
    (MyCustomTag) => {};
    ($other:ident) => {
        webservice::operation_state_ext!($other);
    };
}

pub trait MyCustomTagApiMarker {}

define_api! {
pub struct ConvertImage;

pub struct IndexState {
    // No custom state needed for Index operation
}

impl Operation(Uncached, MyCustomTag) for ConvertImage {
    type Model = Convert;
    type State = IndexState;

    type In = Empty;
    type Out = String;
    type Server = ConverterServer;
    type SessionLookup = NoAuthRequired;

    fn operate(self) -> IronResult<String> {
        // Here we have access to:
        //   self.input: Self::In
        //   self.request_body: Option<Box<dyn std::io::Read>>
        //   self.server: std::sync::Arc<webservice::server::Server>
        //   self.session: &mut <Self::Session as SessionLookup>::Session
        //   self.txn: &database::Transaction

        Ok("HELLO".to_string())
    }
}
}