use async_process::Command;
use log::debug;

use std::fs;
use std::net::SocketAddr;

pub(crate) const ENCLAVE_FS_LOWER: &str = "/mnt/lower";
pub(crate) const ENCLAVE_FS_UPPER: &str = "/mnt/upper";
pub(crate) const ENCLAVE_FS_WORK: &str = "/mnt/overlay-root/work";
pub(crate) const ENCLAVE_FS_OVERLAY_ROOT: &str = "/mnt/overlay-root";

pub(crate) const NBD_DEVICE: &str = "/dev/nbd0";
pub(crate) const DM_VERITY_VOLUME: &str = "rodir";

pub(crate) async fn mount_file_system_nodes() -> Result<(), String> {
    run_mount(&["-t", "proc", "/proc", &format!("{}/proc/", ENCLAVE_FS_OVERLAY_ROOT)]).await?;
    run_mount(&["--rbind", "/sys", &format!("{}/sys/", ENCLAVE_FS_OVERLAY_ROOT)]).await?;
    run_mount(&["--rbind", "/dev", &format!("{}/dev/", ENCLAVE_FS_OVERLAY_ROOT)]).await
}

pub(crate) async fn mount_read_only_file_system() -> Result<(), String> {
    let dm_verity_device = "/dev/mapper/".to_string() + DM_VERITY_VOLUME;

    run_mount(&["-o", "ro", &dm_verity_device, ENCLAVE_FS_LOWER]).await
}

pub(crate) async fn mount_overlay_fs() -> Result<(), String> {
    let lower_dir = ENCLAVE_FS_LOWER.to_string() + "/enclave-fs";
    let overlay_dir_config = format!("lowerdir={},upperdir={},workdir={}", lower_dir, ENCLAVE_FS_UPPER, ENCLAVE_FS_WORK);

    run_mount(&["-t", "overlay", "-o", &overlay_dir_config, "none", ENCLAVE_FS_OVERLAY_ROOT ]).await
}

pub(crate) fn create_overlay_dirs() -> Result<(), String> {
    fs::create_dir(ENCLAVE_FS_LOWER).map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_LOWER, err))?;
    fs::create_dir(ENCLAVE_FS_UPPER).map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_UPPER, err))?;
    fs::create_dir(ENCLAVE_FS_OVERLAY_ROOT).map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_OVERLAY_ROOT, err))?;
    fs::create_dir(ENCLAVE_FS_WORK).map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_WORK, err))?;

    Ok(())
}

pub(crate) struct DMVerityConfig {
    pub hash_offset: u32,

    pub nbd_device: &'static str,

    pub volume_name: &'static str,

    pub root_hash: String
}

pub(crate) async fn setup_dm_verity(config: &DMVerityConfig) -> Result<(), String> {
    let args: [&str; 7] = [
        "open",
        "--hash-offset",
        &config.hash_offset.to_string(),
        &config.nbd_device,
        &config.volume_name,
        &config.nbd_device,
        &config.root_hash
    ];

    run_subprocess("veritysetup", &args).await
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

    let nbd_run_resolv_dir: &str = &format!("{}/run/resolvconf", ENCLAVE_FS_OVERLAY_ROOT);

    let nbd_etc_dir: &str = &format!("{}/etc", ENCLAVE_FS_OVERLAY_ROOT);

    let nbd_run_resolv_file: &str = &format!("{}/run/resolvconf/resolv.conf", ENCLAVE_FS_OVERLAY_ROOT);

    let nbd_etc_resolv_file: &str = &format!("{}/etc/resolv.conf", ENCLAVE_FS_OVERLAY_ROOT);

    fs::create_dir_all(nbd_run_resolv_dir).map_err(|err| format!("Failed creating {} dir. {:?}", nbd_run_resolv_dir, err))?;
    fs::create_dir_all(nbd_etc_dir).map_err(|err| format!("Failed creating {} dir. {:?}", nbd_etc_dir, err))?;

    // We copy resolv.conf from the enclave kernel into the block file mount point
    // so that DNS will work correctly after we do a `chroot`.
    // Using `/usr/bin/mount` to accomplish the same task doesn't seem to work.
    fs::copy(ENCLAVE_RUN_RESOLV_FILE, nbd_run_resolv_file).map_err(|err| {
        format!(
            "Failed copying resolv file from {} to {}. {:?}",
            ENCLAVE_RUN_RESOLV_FILE, nbd_run_resolv_file, err
        )
    })?;
    fs::copy(ENCLAVE_RUN_RESOLV_FILE, nbd_etc_resolv_file).map_err(|err| {
        format!(
            "Failed copying resolv file from {} to {}. {:?}",
            ENCLAVE_RUN_RESOLV_FILE, nbd_etc_resolv_file, err
        )
    })?;

    Ok(())
}

async fn run_mount(args: &[&str]) -> Result<(), String> {
    run_subprocess("/usr/bin/mount", args).await
}

async fn run_subprocess(subprocess_path: &str, args: &[&str]) -> Result<(), String> {
    let mut mount_command = Command::new(subprocess_path);

    mount_command.args(args);

    debug!("Running {} {:?}", subprocess_path, args);
    let mount_process = mount_command
        .spawn()
        .map_err(|err| format!("Failed to run {}. {:?}. Args {:?}", subprocess_path, err, args))?;

    let out = mount_process.output().await.map_err(|err| {
        format!(
            "Error while waiting for {} to finish: {:?}. Args {:?}",
            subprocess_path, err, args
        )
    })?;

    if !out.status.success() {
        Err(format!(
            "Subprocess {} failed with exit code {:?}. Args {:?}",
            subprocess_path, out.status, args
        ))
    } else {
        Ok(())
    }
}
