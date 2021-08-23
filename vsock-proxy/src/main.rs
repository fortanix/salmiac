use vsock_proxy::mode::{parse_console_argument, console_arguments, parse_optional_console_argument};
use vsock_proxy::mode;

use log::{error};

use std::{
    process,
};

fn main() -> Result<(), String> {
    env_logger::init();

    let matches = console_arguments();

    match matches.subcommand() {
        ("parent", Some(args)) => {
            let vsock_port = parse_console_argument::<u32>(args, "vsock-port")?;

            if cfg!(debug_assertions) {
                let remote_port = parse_optional_console_argument::<u32>(args, "remote-port")
                    .and_then(|e| e.ok());

                mode::parent::run(vsock_port, remote_port)?;
            }
            else {
                mode::parent::run(vsock_port, None)?;
            }
        }
        ("enclave", Some(args)) => {
            let vsock_port = parse_console_argument::<u32>(args, "vsock-port")?;

            mode::enclave::run(vsock_port)?;
        }
        _ => {
            error!("Program must be either 'enclave' or 'parent'");
            process::exit(1);
        }
    }

    Ok(())
}
