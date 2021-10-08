use clap::{
    App,
    AppSettings,
    Arg,
    ArgMatches
};
use env_logger;
use log::{error};

use container_converter::ConverterArgs;

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::init();

    let console_arguments = console_arguments();

    let converter_arguments = ConverterArgs::from_console_arguments(&console_arguments)
        .expect("Cannot create console arguments");

    container_converter::run(converter_arguments)
        .await
        .map(|measurements| println!("{}", measurements))
        .map_err(|err| {
            error!("Converter exited with error: {}", err.message);
            err.message
        })
}

fn console_arguments<'a>() -> ArgMatches<'a> {
    App::new("Container converter")
        .about("Converts user docker container to be able to run in AWS Nitro environment")
        .setting(AppSettings::DisableVersion)
        .arg(
            Arg::with_name("image")
                .help("your docker image")
                .long("image")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("parent-image")
                .help("parent image")
                .long("parent-image")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("output-image")
                .help("output image name")
                .long("output-image")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("pull-username")
                .help("user name for a repository that contains input image")
                .long("pull-username")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("pull-password")
                .help("password for a repository that contains input image")
                .long("pull-password")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("push-username")
                .help("user name for a repository that will contain output image")
                .long("push-username")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("push-password")
                .help("password for a repository that will contain output image")
                .long("push-password")
                .takes_value(true)
                .required(false),
        )
        .get_matches()
}