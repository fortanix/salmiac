use std::process::Command;
use std::{process, env};

/// A program that implements a working directory switch before running user application.
/// Working directory different from root ("/") comes from a client images with WORKDIR clause
/// (https://docs.docker.com/engine/reference/builder/#workdir).
/// Because WORKDIR is not currently supported by a Nitro converter (https://github.com/aws/aws-nitro-enclaves-cli/issues/388)
/// we have to perform directory switch manually to prevent any sort of file not found errors from happening.
fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        return Err("Working directory (first argument) and binary to run (second argument) must be supplied.".to_string())
    }

    let workdir = &args[1];
    let bin = &args[2];

    let bin_args = if args.len() > 3 {
        &args[3..]
    } else {
        &[]
    };

    env::set_current_dir(workdir)
        .map_err(|err| format!("Failed to set work dir to {}. {:?}", workdir, err))?;

    let mut client_command = Command::new(bin);
    client_command.args(bin_args);

    let user_program = client_command.spawn()
        .map_err(|err| format!("Failed to start subprocess {}. {:?}", bin, err))?;

    let result = user_program.wait_with_output()
        .map_err(|err| format!("Failed to run subprocess {}. {:?}", bin, err))?;

    let exit_code = result.status.code().unwrap_or(-1);

    process::exit(exit_code)
}
