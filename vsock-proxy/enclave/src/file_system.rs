use async_process::Command;
use log::{debug};

use std::fs;
use std::net::SocketAddr;

pub(crate) const ENCLAVE_FS_ROOT: &str = "/mnt/enclave-fs";

const NBD_DEVICE: &str = "/dev/nbd0";

pub(crate) async fn mount_file_system() -> Result<(), String> {
    run_mount(&["-t", "proc", "/proc", "/mnt/enclave-fs/proc/"]).await?;
    run_mount(&["--rbind", "/sys", "/mnt/enclave-fs/sys/"]).await?;
    run_mount(&["--rbind", "/dev", "/mnt/enclave-fs/dev/"]).await
}

pub(crate) async fn mount_nbd_device() -> Result<(), String> {
    run_mount(&[NBD_DEVICE, "/mnt"]).await?;

    //check that mount was successful
    let mounted_dir = fs::read_dir(ENCLAVE_FS_ROOT)
        .map_err(|err| format!("Failed reading dir {}. {:?}", ENCLAVE_FS_ROOT, err))?;

    for contents in mounted_dir {
        match contents {
            Ok(dir_entry) => {
                debug!("Mounted {} dir contains {}", ENCLAVE_FS_ROOT, dir_entry.path().display())
            }
            Err(err) => {
                return Err(format!("Mounted {} dir has corrupted entry. {:?}", ENCLAVE_FS_ROOT, err))
            }
        }
    }

    Ok(())
}

pub(crate) async fn run_nbd_client(address: SocketAddr) -> Result<(), String> {
    let args: [&str; 4] = [&address.ip().to_string(), &address.port().to_string(), "-N", "enclave-fs"];
    // NBD client exits with zero if it is able to connect to the server
    // and create /dev/nbdX device. After that we can `mount` said device
    // and use it to access the block file in `parent`.
    run_subprocess("nbd-client", &args).await
}

pub(crate) fn copy_dns_file_to_mount() -> Result<(), String> {
    const ENCLAVE_RUN_RESOLV_FILE: &str = "/run/resolvconf/resolv.conf";

    const NBD_RUN_RESOLV_DIR: &str = "/mnt/enclave-fs/run/resolvconf";

    const NBD_ETC_DIR: &str = "/mnt/enclave-fs/etc";

    const NBD_RUN_RESOLV_FILE: &str = "/mnt/enclave-fs/run/resolvconf/resolv.conf";

    const NBD_ETC_RESOLV_FILE: &str = "/mnt/enclave-fs/etc/resolv.conf";

    fs::create_dir_all(NBD_RUN_RESOLV_DIR)
        .map_err(|err| format!("Failed creating {} dir. {:?}", NBD_RUN_RESOLV_DIR, err))?;
    fs::create_dir_all(NBD_ETC_DIR)
        .map_err(|err| format!("Failed creating {} dir. {:?}", NBD_ETC_DIR, err))?;

    // We copy resolv.conf from the enclave kernel into the block file mount point
    // so that DNS will work correctly after we do a `chroot`.
    // Using `/usr/bin/mount` to accomplish the same task doesn't seem to work.
    fs::copy(ENCLAVE_RUN_RESOLV_FILE, NBD_RUN_RESOLV_FILE)
        .map_err(|err| format!("Failed copying resolv file from {} to {}. {:?}", ENCLAVE_RUN_RESOLV_FILE, NBD_RUN_RESOLV_FILE, err))?;
    fs::copy(ENCLAVE_RUN_RESOLV_FILE, NBD_ETC_RESOLV_FILE)
        .map_err(|err| format!("Failed copying resolv file from {} to {}. {:?}", ENCLAVE_RUN_RESOLV_FILE, NBD_ETC_RESOLV_FILE, err))?;

    Ok(())
}

async fn run_mount(args: &[&str]) -> Result<(), String> {
    run_subprocess("/usr/bin/mount", args).await
}

async fn run_subprocess(subprocess_path: &str, args: &[&str]) -> Result<(), String> {
    let mut mount_command = Command::new(subprocess_path);

    mount_command.args(args);

    let mount_process = mount_command
        .spawn()
        .map_err(|err| format!("Failed to run {}. {:?}. Args {:?}", subprocess_path, err, args))?;

    let out = mount_process
        .output()
        .await
        .map_err(|err| format!("Error while waiting for {} to finish: {:?}. Args {:?}", subprocess_path, err, args))?;

    if !out.status.success() {
        Err(format!("Subprocess {} failed with exit code {:?}. Args {:?}", subprocess_path, out.status, args))
    } else {
        Ok(())
    }
}