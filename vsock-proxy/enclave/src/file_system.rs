use async_process::{Command, Stdio};
use log::debug;

use futures::AsyncWriteExt;
use std::fs;
use std::net::IpAddr;

pub(crate) const ENCLAVE_FS_LOWER: &str = "/mnt/lower";
pub(crate) const ENCLAVE_FS_RW_ROOT: &str = "/mnt/overlayfs";
pub(crate) const ENCLAVE_FS_UPPER: &str = "/mnt/overlayfs/upper";
pub(crate) const ENCLAVE_FS_WORK: &str = "/mnt/overlayfs/work";
pub(crate) const ENCLAVE_FS_OVERLAY_ROOT: &str = "/mnt/overlay-root";
pub(crate) const CRYPT_KEYFILE: &str = "/etc/rw-keyfile";

pub(crate) const NBD_DEVICE: &str = "/dev/nbd0";
pub(crate) const NBD_RW_DEVICE: &str = "/dev/nbd1";
pub(crate) const DEVICE_MAPPER: &str = "/dev/mapper/";

pub(crate) const DM_VERITY_VOLUME: &str = "rodir";

pub(crate) const DM_CRYPT_DEVICE: &str = "cryptdevice";

pub(crate) async fn mount_file_system_nodes() -> Result<(), String> {
    run_mount(&["-t", "proc", "/proc", &format!("{}/proc/", ENCLAVE_FS_OVERLAY_ROOT)]).await?;
    run_mount(&["--rbind", "/sys", &format!("{}/sys/", ENCLAVE_FS_OVERLAY_ROOT)]).await?;
    run_mount(&["--rbind", "/dev", &format!("{}/dev/", ENCLAVE_FS_OVERLAY_ROOT)]).await
}

pub(crate) async fn mount_read_only_file_system() -> Result<(), String> {
    let dm_verity_device = DEVICE_MAPPER.to_string() + DM_VERITY_VOLUME;

    run_mount(&["-o", "ro", &dm_verity_device, ENCLAVE_FS_LOWER]).await
}

pub(crate) async fn generate_keyfile() -> Result<(), String> {
    run_subprocess(
        "/bin/dd",
        &[
            "bs=1024",
            "count=4",
            "if=/dev/random",
            &format!("of={}", CRYPT_KEYFILE),
            "iflag=fullblock",
        ],
    )
    .await
}

pub(crate) async fn mount_read_write_file_system() -> Result<(), String> {
    let crypt_setup_args: [&str; 5] = ["open", "--type", "plain", NBD_RW_DEVICE, DM_CRYPT_DEVICE];

    run_subprocess0("cryptsetup", &crypt_setup_args, &["testkey"]).await?;

    let dm_crypt_mapped_device = DEVICE_MAPPER.to_string() + DM_CRYPT_DEVICE;

    run_subprocess("mkfs.ext4", &[&dm_crypt_mapped_device]).await?;

    run_mount(&[&dm_crypt_mapped_device, ENCLAVE_FS_RW_ROOT]).await
}

pub(crate) async fn mount_overlay_fs() -> Result<(), String> {
    let lower_dir = ENCLAVE_FS_LOWER.to_string() + "/enclave-fs";
    let overlay_dir_config = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower_dir, ENCLAVE_FS_UPPER, ENCLAVE_FS_WORK
    );

    run_mount(&["-t", "overlay", "-o", &overlay_dir_config, "none", ENCLAVE_FS_OVERLAY_ROOT]).await
}

pub(crate) fn create_overlay_dirs() -> Result<(), String> {
    fs::create_dir(ENCLAVE_FS_LOWER).map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_LOWER, err))?;
    fs::create_dir(ENCLAVE_FS_RW_ROOT).map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_UPPER, err))?;
    fs::create_dir(ENCLAVE_FS_OVERLAY_ROOT)
        .map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_OVERLAY_ROOT, err))?;

    Ok(())
}

pub(crate) fn create_overlay_rw_dirs() -> Result<(), String> {
    fs::create_dir(ENCLAVE_FS_WORK).map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_WORK, err))?;
    fs::create_dir(ENCLAVE_FS_UPPER).map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_UPPER, err))?;

    Ok(())
}

pub(crate) struct DMVerityConfig {
    pub hash_offset: u64,

    pub nbd_device: &'static str,

    pub volume_name: &'static str,

    pub root_hash: String,
}

pub(crate) async fn setup_dm_verity(config: &DMVerityConfig) -> Result<(), String> {
    let args: [&str; 7] = [
        "open",
        "--hash-offset",
        &config.hash_offset.to_string(),
        &config.nbd_device,
        &config.volume_name,
        &config.nbd_device,
        &config.root_hash,
    ];

    run_subprocess("veritysetup", &args).await
}

pub(crate) async fn run_nbd_client(server_address: IpAddr, block_file_port: u16, mount_name: &str) -> Result<(), String> {
    let args: [&str; 4] = [&server_address.to_string(), &block_file_port.to_string(), "-N", mount_name];
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
    run_subprocess0(subprocess_path, args, &[]).await
}

async fn run_subprocess0(subprocess_path: &str, args: &[&str], stdin_args: &[&str]) -> Result<(), String> {
    let mut command = Command::new(subprocess_path);

    command.args(args);

    if !stdin_args.is_empty() {
        command.stdin(Stdio::piped());
    }

    debug!(
        "Running subprocess {} {:?}. Stdin args {:?}",
        subprocess_path, args, stdin_args
    );
    let mut process = command
        .spawn()
        .map_err(|err| format!("Failed to run subprocess {}. {:?}. Args {:?}", subprocess_path, err, args))?;

    if let Some(mut stdin) = process.stdin.as_mut() {
        for arg in stdin_args {
            AsyncWriteExt::write_all(&mut stdin, arg.as_bytes())
                .await
                .map_err(|err| format!("Cannot write to stdin {:?}", err))?;
        }
    }

    let out = process.output().await.map_err(|err| {
        format!(
            "Error while waiting for subprocess {} to finish: {:?}. Args {:?}",
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
