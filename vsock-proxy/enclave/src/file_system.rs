use async_process::Command;
use log::debug;

use std::fs;
use std::net::IpAddr;
use std::path::Path;

const ENCLAVE_FS_LOWER: &str = "/mnt/lower";
const ENCLAVE_FS_RW_ROOT: &str = "/mnt/overlayfs";
const ENCLAVE_FS_UPPER: &str = "/mnt/overlayfs/upper";
const ENCLAVE_FS_WORK: &str = "/mnt/overlayfs/work";
pub(crate) const ENCLAVE_FS_OVERLAY_ROOT: &str = "/mnt/overlay-root";

const NBD_DEVICE: &str = "/dev/nbd0";
const NBD_RW_DEVICE: &str = "/dev/nbd1";
const DEVICE_MAPPER: &str = "/dev/mapper/";

const DM_VERITY_VOLUME: &str = "rodir";

const DM_CRYPT_DEVICE: &str = "cryptdevice";

pub(crate) async fn mount_file_system_nodes() -> Result<(), String> {
    run_mount(&["-t", "proc", "/proc", &format!("{}/proc/", ENCLAVE_FS_OVERLAY_ROOT)]).await?;
    run_mount(&["--rbind", "/sys", &format!("{}/sys/", ENCLAVE_FS_OVERLAY_ROOT)]).await?;
    run_mount(&["--rbind", "/dev", &format!("{}/dev/", ENCLAVE_FS_OVERLAY_ROOT)]).await
}

pub(crate) async fn mount_read_only_file_system() -> Result<(), String> {
    let dm_verity_device = DEVICE_MAPPER.to_string() + DM_VERITY_VOLUME;

    run_mount(&["-o", "ro", &dm_verity_device, ENCLAVE_FS_LOWER]).await
}

pub(crate) async fn generate_keyfile(file_path: &Path) -> Result<(), String> {
    run_subprocess(
        "/bin/dd",
        &[
            "bs=1024",
            "count=4",
            "if=/dev/random",
            &format!("of={}", file_path.display()),
            "iflag=fullblock",
        ],
    )
    .await
}

/// Formats the device as a luks2 device. This step must not be performed on a
/// device which already contains usable data in it. It creates a luks2
/// style header on the device and configures one of the key slots.
/// # Notes
/// The minimum size of a luks2 header is 16MB - it is important that the size
/// of the device meets this requirement (RW_BLOCK_FILE_DEFAULT_SIZE).
async fn luks_format_device(key_path: &Path, device_path: &str) -> Result<(), String> {
    let key_path_as_str = key_path
        .to_str()
        .ok_or(format!("Failed converting path {} to string", key_path.display()))?;

    let luks_format_args = ["luksFormat", "-q", "--type", "luks2", device_path, key_path_as_str];
    run_subprocess("cryptsetup", &luks_format_args).await
}

pub(crate) async fn mount_read_write_file_system(crypt_file: &Path) -> Result<(), String> {
    luks_format_device(crypt_file, NBD_RW_DEVICE).await?;

    let crypt_setup_args: [&str; 7] = [
        "open",
        "--key-file",
        crypt_file
            .to_str()
            .ok_or(format!("Failed converting path {} to string", crypt_file.display()))?,
        "--type",
        "luks2",
        NBD_RW_DEVICE,
        DM_CRYPT_DEVICE,
    ];

    run_subprocess("cryptsetup", &crypt_setup_args).await?;

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
    hash_offset: u64,

    nbd_device: &'static str,

    volume_name: &'static str,

    root_hash: String,
}

impl DMVerityConfig {
    pub(crate) fn new(hash_offset: u64, root_hash: String) -> Self {
        DMVerityConfig {
            hash_offset,
            nbd_device: NBD_DEVICE,
            volume_name: DM_VERITY_VOLUME,
            root_hash,
        }
    }
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

pub(crate) fn copy_startup_binary_to_mount(startup_binary: &str) -> Result<(), String> {
    const STARTUP_PATH: &str = "/opt/fortanix/enclave-os";

    let from = STARTUP_PATH.to_string() + startup_binary;
    let to = ENCLAVE_FS_OVERLAY_ROOT.to_string() + startup_binary;

    fs::copy(&from, &to).map_err(|err| format!("Failed to copy enclave startup binary from {} to {}. {:?}", from, to, err))?;

    Ok(())
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

pub(crate) async fn unmount_overlay_fs() -> Result<(), String> {
    run_unmount(&[ENCLAVE_FS_RW_ROOT]).await?;
    run_unmount(&["-R", ENCLAVE_FS_LOWER]).await?;
    run_unmount(&["-v", ENCLAVE_FS_OVERLAY_ROOT]).await
}

pub(crate) async fn unmount_file_system_nodes() -> Result<(), String> {
    run_unmount(&[&format!("{}/proc/", ENCLAVE_FS_OVERLAY_ROOT)]).await?;
    run_unmount(&["-R", &format!("{}/sys/", ENCLAVE_FS_OVERLAY_ROOT)]).await?;
    run_unmount(&["-R", &format!("{}/dev/", ENCLAVE_FS_OVERLAY_ROOT)]).await
}

pub(crate) async fn close_dm_crypt_device() -> Result<(), String> {
    run_subprocess("cryptsetup", &["close", DM_CRYPT_DEVICE]).await
}

pub(crate) async fn close_dm_verity_volume() -> Result<(), String> {
    run_subprocess("veritysetup", &["close", DM_VERITY_VOLUME]).await
}

async fn run_unmount(args: &[&str]) -> Result<(), String> {
    run_subprocess("/usr/bin/umount", args).await
}

async fn run_mount(args: &[&str]) -> Result<(), String> {
    run_subprocess("/usr/bin/mount", args).await
}

async fn run_subprocess(subprocess_path: &str, args: &[&str]) -> Result<(), String> {
    let mut command = Command::new(subprocess_path);

    command.args(args);

    debug!("Running subprocess {} {:?}.", subprocess_path, args);
    let process = command
        .spawn()
        .map_err(|err| format!("Failed to run subprocess {}. {:?}. Args {:?}", subprocess_path, err, args))?;

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
