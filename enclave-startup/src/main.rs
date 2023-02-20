use env_logger;
use log::{info, warn};
use nix::unistd::{chown, Gid, Uid};
use users::{get_group_by_name, get_user_by_name, gid_t, uid_t, User};

use std::env;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// A program that sets environment for a client application in the chroot environment (https://man7.org/linux/man-pages/man2/chroot.2.html).
/// It performs the following:
/// - Switches working directory, user and group before running the application.
///     Working directory and user/group come from a client images with following clauses:
///     (https://docs.docker.com/engine/reference/builder/#workdir),
///     (https://docs.docker.com/engine/reference/builder/#user).
///     Because neither WORKDIR or USER are currently supported by a Nitro converter
///     we have to perform switch manually to prevent any sort of access and file not found errors from happening;
/// - Updates ownership of std streams for the client application;
/// - Sets host name (https://man7.org/linux/man-pages/man7/hostname.7.html).
fn main() -> Result<(), String> {
    env_logger::init();
    let args: Vec<String> = env::args().collect();

    let workdir = &args[1];
    let user = &args[2];
    let group = &args[3];
    let hostname = &args[4];
    let bin = &args[5];
    let bin_args = if args.len() > 6 { &args[6..] } else { &[] };

    env::set_current_dir(workdir).map_err(|err| format!("Failed to set work dir to {}. {:?}", workdir, err))?;

    // Fetch UID/GID for the client command
    let res = fetch_uid_gid(user, group)?;
    let uid = res.uid();
    let gid = res.primary_group_id();

    // Update ownership of std streams of the current process to User res
    update_std_stream_owner(uid, gid)?;

    if !hostname.is_empty() {
        nix::unistd::sethostname(&hostname).map_err(|err| format!("Failed setting host name to {}. {:?}", hostname, err))?;
        info!("Set host name to {}", hostname);
    }

    // Exec the client program with the relevant user/group
    let mut client_command = Command::new(bin);
    client_command.args(bin_args);
    client_command.uid(uid);
    client_command.gid(gid);

    // on success this function will not return, not returning has the same
    // implications as calling `process::exit`
    let err = client_command.exec();

    Err(format!("Failed to run subprocess {}. {:?}", bin, err))
}

fn update_std_stream_owner(uid: uid_t, gid: gid_t) -> Result<(), String> {
    let std_stream_paths = ["/proc/self/fd/0", "/proc/self/fd/1", "/proc/self/fd/2"];
    let mut status = true;

    for path in std_stream_paths {
        // TODO: Use chown from "std" crate once their stable feature is out. This
        // will avoid having an additional dependency "nix" into enclave startup code
        match chown(path, Some(Uid::from(uid)), Some(Gid::from(gid))) {
            Ok(_) => {
                info!("Successfully updated ownership of {:?}", path);
            }
            Err(e) => {
                warn!("Unable to change ownership of {:?} : {:?}", path, e.to_string());
                status = false;
            }
        }
    }

    if !status {
        return Err(format!("Unable to update ownership of one or more std streams"));
    }

    Ok(())
}

fn fetch_uid_gid(user: &String, group: &String) -> Result<User, String> {
    let mut user_id = 0;
    let mut group_id = 0;
    let mut gid_found = false;
    let mut uid_found = false;

    // If user is empty, use default user_id of 0 (root)
    if user.is_empty() {
        uid_found = true;
    }

    // Look up the user by name, if found, set uid
    // and if group is not set, use the primary gid of
    // the user
    match get_user_by_name(user) {
        None => {
            warn!("User {:?} not found by name", user);
        }
        Some(u) => {
            info!("Found user by name {:?}, setting uid to {:?}", user, u.uid());
            user_id = u.uid();
            uid_found = true;
            if group.is_empty() {
                info!("Setting primary gid={:?} of user {:?}", u.primary_group_id(), user);
                group_id = u.primary_group_id();
                gid_found = true;
            }
        }
    };

    // If gid is not found and group is set, try to find
    // group by name
    if !gid_found && !group.is_empty() {
        match get_group_by_name(group) {
            None => {
                warn!("Group {:?} not found by name", group);
            }
            Some(g) => {
                info!("Found group by name {:?}, setting gid to {:?}", group, g.gid());
                group_id = g.gid();
                gid_found = true;
            }
        };
    }

    // If uid is still not found, parse the user string
    // for an ID
    if !uid_found && !user.is_empty() {
        user_id = parse_id_str(user)?;
        uid_found = true;
    }

    // If gid is still not found, parse the group string
    // for an ID or set the group to default root group
    if !gid_found {
        if !group.is_empty() {
            group_id = parse_id_str(group)?;
        } else {
            info!("Group not set. Default to root group.");
            group_id = 0;
        }
        gid_found = true;
    }

    if uid_found && gid_found {
        let res = User::new(user_id, user, group_id);
        Ok(res)
    } else {
        Err(format!("Unable to find user/group - {:?}:{:?}", user, group))
    }
}

fn parse_id_str(id_str: &String) -> Result<u32, String> {
    match String::from(id_str).trim().parse::<u32>() {
        Ok(id) => {
            info!("Parsed string {:?} as id {:?}", id_str, id);
            Ok(id)
        }
        Err(e) => Err(format!(
            "String {:?} could not be parsed for an ID: {:?}",
            id_str,
            e.to_string()
        )),
    }
}
