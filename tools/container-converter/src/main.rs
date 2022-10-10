use api_model::NitroEnclavesConversionRequest;
use clap::{App, AppSettings, Arg, ArgMatches};
use env_logger;
use log::error;

use std::fs;

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let console_arguments = console_arguments();

    let request_file_path = console_arguments
        .value_of("request-file")
        .expect("Request file must be provided");

    let request_file =
        fs::read_to_string(request_file_path).map_err(|err| format!("Failed reading request file. {:?}", err))?;

    let request = serde_json::from_str::<NitroEnclavesConversionRequest>(&request_file)
        .map_err(|err| format!("Failed deserializing conversion request. {:?}", err))?;

    match container_converter::run(request, console_arguments.is_present("use-file-system")).await {
        Ok(response) => {
            println!("{:?}", response);
            Ok(())
        }
        Err(err) => {
            error!("Converter exited with error: {}", err.message);
            Err(err.message)
        }
    }
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Container converter")
        .about("Converts user docker container to be able to run in AWS Nitro environment")
        .setting(AppSettings::DisableVersion)
        .arg(
            Arg::with_name("request-file")
                .help("Path to a file that contains conversion request")
                .long("request-file")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("use-file-system")
                .long("use-file-system")
                .takes_value(false)
                .required(false),
        )
        .get_matches()
}
