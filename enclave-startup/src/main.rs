use std::process::Command;
use std::{env};
use std::os::unix::process::CommandExt;

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
    let user = &args[2];
    let group = &args[3];
    let bin = &args[4];

    let bin_args = if args.len() > 5 {
        &args[5..]
    } else {
        &[]
    };

    env::set_current_dir(workdir)
        .map_err(|err| format!("Failed to set work dir to {}. {:?}", workdir, err))?;

    let mut client_command = if user != "root" {
        let mut result = Command::new("runuser");

        result.arg("-u");
        result.arg(user);

        if group != "root" {
            result.arg("-g");
            result.arg(group);
        }
        
        result.arg(bin);

        result
    } else {
        Command::new(bin)
    };

    client_command.args(bin_args);

    // on success this function will not return, not returning has the same
    // implications as calling `process::exit`
    let err = client_command.exec();

    Err(format!("Failed to run subprocess {}. {:?}", bin, err))
}
