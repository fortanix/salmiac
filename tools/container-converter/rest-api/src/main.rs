use clap::{ArgMatches, App, AppSettings, Arg};
use env_logger;
use iron::{Iron, Request, Response, IronResult};
use iron::Plugin;
use iron::status;
use router::Router;
use log::info;
use tokio::runtime::{Runtime, Handle};

use app::ConverterArgs;

fn main() -> Result<(), String> {
    env_logger::init();

    let console_arguments = console_arguments();

    let port = console_arguments.value_of("port")
        .map(|e| u16::from_str_radix(&e, 10))
        .expect("Port argument is missing")
        .expect("Cannot parse port argument");

    let rt = Runtime::new().expect("Failed to create tokio runtime");
    let mut router = Router::new();

    router.post("/convert",
                move |req : &mut Request| convert_handler(req, rt.handle()),
                "convert_handler");

    Iron::new(router).http(("localhost", port))
        .expect("Failed to start http server");

    Ok(())
}

fn convert_handler(req: &mut Request, handle : &Handle) -> IronResult<Response> {
    fn run_converter(args : ConverterArgs, handle : &Handle) -> IronResult<Response> {
        let converter_result = handle.block_on(app::run(args));

        match converter_result {
            Ok(result) => {
                Ok(Response::with((status::Ok, result)))
            }
            Err(err) => {
                Ok(Response::with((status::InternalServerError, format!("{:?}", err))))
            }
        }
    }

    match req.get::<bodyparser::Struct<ConverterArgs>>() {
        Ok(Some(args)) => {
            run_converter(args, handle)
        },
        Ok(None) => {
            Ok(Response::with((status::BadRequest, "No body")))
        },
        Err(err) => {
            Ok(Response::with((status::BadRequest, format!("{:?}", err))))
        }
    }
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
