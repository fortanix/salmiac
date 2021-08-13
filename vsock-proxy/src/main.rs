use vsock_proxy::mode::{
    parse_console_argument,
    console_arguments,
};
use vsock_proxy::mode;

use threadpool::ThreadPool;
use log::{error};

use std::{
    process,
    env
};

fn main() -> Result<(), String> {
    env::set_var("RUST_LOG","debug");

    env_logger::init();

    let matches = console_arguments();

    match matches.subcommand() {
        ("parent", Some(args)) => {
            let vsock_port = parse_console_argument::<u32>(args, "vsock-port")?;
            let remote_port = parse_console_argument::<u32>(args, "remote-port")?;
            let thread_pool = ThreadPool::new(2);

            mode::parent::run(vsock_port, remote_port, thread_pool)?;
        }
        ("enclave", Some(args)) => {
            let vsock_port = parse_console_argument::<u32>(args, "vsock-port")?;
            let thread_pool = ThreadPool::new(2);

            mode::enclave::run(vsock_port, thread_pool)?;
        }
        _ => {
            error!("Program must be either 'enclave' or 'parent'");
            process::exit(1);
        }
    }

    process::exit(0);
}
