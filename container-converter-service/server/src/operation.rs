use iron::{IronResult, Response, IronError};
use iron::status::Status;

use webservice::define_api;
use webservice::session_lookup::NoAuthRequired;
use container_converter::ConverterArgs;

use crate::ConverterServer;
use crate::Convert;

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
                    let error = format!("{:?}", err);

                    let mut response = Response::new();
                    response.status = Some(Status::InternalServerError);
                    response.body = Some(Box::new(error));

                    Err(IronError {
                        error: Box::new(err),
                        response
                    })
                }
            }
        }
    }
}
