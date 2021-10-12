use iron::IronResult;

use webservice::define_api;
use container_converter::ConverterArgs;
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

    pub struct NoState { }

    impl Operation(Uncached, MyCustomTag) for ConvertImage {
        type Model = Convert;
        type State = NoState;

        type In = ConverterArgs;
        type Out = String;
        type Server = ConverterServer;
        type SessionLookup = NoAuthRequired;

        fn operate(self) -> IronResult<String> {
            let handle = self.server.tokio().handle();
            let converter_result = handle.block_on(container_converter::run(self.input));

            match converter_result {
                Ok(result) => {
                    Ok(result)
                }
                Err(err) => {
                    Ok(format!("{:?}", err))
                }
            }
        }
    }
}
