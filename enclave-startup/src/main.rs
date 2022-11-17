use std::env;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// A program that switches working directory, user and group before running the application.
/// Working directory and user/group come from a client images with following clauses:
/// (https://docs.docker.com/engine/reference/builder/#workdir),
/// (https://docs.docker.com/engine/reference/builder/#user).
/// Because neither WORKDIR or USER are currently supported by a Nitro converter
/// we have to perform switch manually to prevent any sort of access and file not found errors from happening.
fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    let workdir = &args[1];
    let user = &args[2];
    let group = &args[3];
    let bin = &args[4];

    let bin_args = if args.len() > 5 { &args[5..] } else { &[] };

    env::set_current_dir(workdir).map_err(|err| format!("Failed to set work dir to {}. {:?}", workdir, err))?;
    
    let mut client_command = Command::new("runuser");
    client_command.args(&["-u", user, "-g", group]);

    // '--' is a separator between runuser and client's bin arguments.
    // With separator in place client's bin arguments are not able to overwrite runuser
    // arguments with the same name.
    client_command.arg("--");
    client_command.arg(bin);
    client_command.args(bin_args);

    // on success this function will not return, not returning has the same
    // implications as calling `process::exit`
    let err = client_command.exec();

    Err(format!("Failed to run subprocess {}. {:?}", bin, err))
}
