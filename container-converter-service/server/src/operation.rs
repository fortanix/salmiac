use iron::IronResult;

use webservice::define_api;
use webservice::session_lookup::NoAuthRequired;
use container_converter::ConverterArgs;
use crate::ConverterServer;
use crate::Convert;

macro_rules! define_api {
    { $($operation_def:tt)* } => {
        webservice::define_api_ex! {
            (top_level_ext, operation_ext, operation_state_ext)
            $($operation_def)*
        }
    };
}

define_api! {
    pub struct ConvertImage;

    pub struct ConvertImageState { }

    impl Operation for ConvertImage {
        type Model = Convert;
        type State = ConvertImageState;

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
