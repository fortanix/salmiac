use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::Path;

use log::{error, info};
use nix::sys::statvfs::FsFlags;
use rand::{thread_rng, Rng};
use sdkms::api_model::{Blob, EncryptResponse};
use serde::{Deserialize, Serialize};
use serde_json;
use shared::{run_subprocess, run_subprocess_with_output_setup, CommandOutputConfig};

use crate::certificate::CertificateResult;
use crate::dsm_key_config::{dsm_dec_with_overlayfs_key, dsm_enc_with_overlayfs_key, DEFAULT_DSM_ENDPOINT};

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
const DM_CRYPT_FOLDER: &str = "/run/cryptsetup";
const CRYPT_KEYFILE: &str = "/etc/rw-keyfile";
const CRYPT_KEYSIZE: usize = 512;
const TOKEN_IN_FILE: &str = "/etc/token-in.json";
const TOKEN_OUT_FILE: &str = "/etc/token-out.json";
const MAX_TOKEN_SIZE: usize = 4096;

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct LuksToken {
    // Luks2 token type expects two mandatory
    // fields with key name "type" and "keyslots"
    #[serde(rename = "type")]
    pub token_type: String,
    #[serde(rename = "keyslots")]
    pub key_slots: Vec<String>,
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isvsvn: Option<u32>,
    pub tag: Blob,
    pub enc_key: Blob,
    pub iv: Blob,
}

pub struct FsMountOptions {
    pub is_tmp_exec: bool,
}

#[derive(PartialEq)]
enum TokenOp {
    Export,
    Import,
}

pub(crate) enum FileSystemNode {
    Proc,
    TreeNode(&'static str),
    File(&'static str),
}

pub(crate) async fn mount_file_system_nodes(nodes: &[FileSystemNode], mount_options: FsMountOptions) -> Result<(), String> {
    for node in nodes {
        match node {
            FileSystemNode::Proc => {
                run_mount(&["-t", "proc", "/proc", &format!("{}/proc/", ENCLAVE_FS_OVERLAY_ROOT)]).await?;
            }
            FileSystemNode::TreeNode(node_path) => {
                let formatted_mount_point_str = format!("{}{node_path}", ENCLAVE_FS_OVERLAY_ROOT, node_path = node_path);
                let mut mount_args = vec!["--rbind", node_path, &formatted_mount_point_str];
                if node_path.clone() == "/tmp" && mount_options.is_tmp_exec {
                    mount_args.push("-o");
                    mount_args.push("exec");
                    // Make the tmp directory of the enclave base image executable first
                    // since this is the directory that is mounted into client's
                    // overlay root.
                    run_mount(&["/tmp", "-o", "remount,exec"]).await?;
                }
                run_mount(&mount_args).await?;
            }
            FileSystemNode::File(file_path) => {
                run_mount(&[
                    "--bind",
                    file_path,
                    &format!("{}{file_path}", ENCLAVE_FS_OVERLAY_ROOT, file_path = file_path),
                ])
                .await?;
            }
        }
    }

    Ok(())
}

pub(crate) async fn mount_read_only_file_system() -> Result<(), String> {
    let dm_verity_device = DEVICE_MAPPER.to_string() + DM_VERITY_VOLUME;
    run_mount(&["-o", "ro", &dm_verity_device, ENCLAVE_FS_LOWER]).await
}

pub(crate) fn fetch_fs_mount_options() -> Result<FsMountOptions, String> {
    let ro_only_mnt_tmp_path = Path::new(ENCLAVE_FS_LOWER).join("tmp");
    let statfs_res = nix::sys::statvfs::statvfs(ro_only_mnt_tmp_path.as_path())
        .map_err(|e| format!("Unable to obtain stat info on client's tmp fs : {:?}", e))?;
    Ok(FsMountOptions {
        is_tmp_exec: !statfs_res.flags().contains(FsFlags::ST_NOEXEC),
    })
}

pub(crate) fn generate_keyfile() -> Result<Vec<u8>, String> {
    // Generate key material from random data generator
    let mut arr = vec![0u8; CRYPT_KEYSIZE];
    thread_rng()
        .try_fill(&mut arr[..])
        .map_err(|err| format!("Unable to fill key buffer with random data : {:?}", err))?;

    // Write the key contents to the keyfile
    let mut key_file = fs::File::create(CRYPT_KEYFILE).map_err(|err| format!("Unable to create key file : {:?}", err))?;
    key_file
        .write(&*arr.clone())
        .map_err(|err| format!("Unable to write to key file: {:?}", err))?;

    // Also return the key material. This may be used by the caller if the
    // encrypted key needs to be stored in the luks header
    Ok(arr)
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

/// Check if the device is a valid crypt luks device
/// Passing --type specifically checks for the version of luks used
/// -v option provides a verbose output rather than returning 0 or 1
/// for success or failure
async fn is_luks_device(device_path: &str) -> Result<async_process::Output, String> {
    let args = ["isLuks", "--type", "luks2", "-v", device_path];

    // Calling `cryptsetup` with `isLuks` argument is expected to fail if no cryptsetup device has been setup prior.
    // To not pollute the console with the errors from `crypsetup` we pipe the stdout/err when calling the sub process
    run_subprocess_with_output_setup("cryptsetup", &args, CommandOutputConfig::all_piped()).await
}

/// Export or import a token object from the given luks2 device. Always looks for the
/// token with ID 0 and expects a file where the token is read from or written to.
async fn update_luks_token(device_path: &str, token_path: &str, op: TokenOp) -> Result<(), String> {
    let op_str = if op == TokenOp::Import { "import" } else { "export" };

    info!("{:?} token for device {:?} at {:?}", &op_str, &device_path, &token_path);
    let token_args = ["token", op_str, "--token-id", "0", "--json-file", token_path, device_path];
    run_subprocess("cryptsetup", &token_args).await
}

/// Opens the output token file. Parses it into a luks2 token object.
/// After parsing the token to obtain parameters needed to access DSM,
/// fetch the overlay fs key used to wrap the RW volume passkey.
async fn get_key_from_out_token(
    env_vars: &[(String, String)],
    cert_list: Option<&mut CertificateResult>,
) -> Result<(), String> {
    // Open and parse the dmcrypt volume token file
    let mut token_file = fs::File::open(TOKEN_OUT_FILE).map_err(|err| format!("Unable to open token out file : {:?}", err))?;
    let mut token_contents = [0; MAX_TOKEN_SIZE];
    let token_size = token_file
        .read(&mut token_contents)
        .map_err(|err| format!("Unable to read from token out file : {:?}", err))?;

    info!(
        "Token contents are >> {:?} : {:?}",
        std::str::from_utf8(&token_contents.clone()).map_err(|e| format!("Unable to convert token contents to utf8 : {:?}", e)),
        token_size
    );

    let token_json_obj: LuksToken = serde_json::from_slice(token_contents.split_at(token_size).0)
        .map_err(|err| format!("Unable to decode Token json object from slice : {:?}", err))?;

    // Fetch the decrypted volume passkey
    let dec_resp = dsm_dec_with_overlayfs_key(
        cert_list,
        env_vars,
        token_json_obj.enc_key,
        token_json_obj.iv,
        token_json_obj.tag,
    )?;

    // Create the key file
    let key_file = fs::File::create(CRYPT_KEYFILE).map_err(|err| format!("Unable to create key file : {:?}", err));
    let key_contents = dec_resp.plain;

    key_file?
        .write(&*key_contents)
        .map_err(|err| format!("Unable to write to key file: {:?}", err))?;

    info!("Key file created.");

    Ok(())
}

/// Generates the passkey file used to encrypt the RW block device
/// Returns a boolean value to indicate whether it is the first run
/// of the app or not. When it is the first run of the app, the caller
/// of this function creates a ext4 filesystem on it after opening
/// the device
async fn get_key_file(
    env_vars: &[(String, String)],
    cert_list: Option<&mut CertificateResult>,
    conv_use_dsm_key: bool,
) -> Result<bool, String> {
    let device_path = NBD_RW_DEVICE;
    let key_path = Path::new(CRYPT_KEYFILE);

    match is_luks_device(device_path).await {
        Ok(_) => {
            info!("Luks2 device found. Attempting to fetch luks2 token.");
            match update_luks_token(device_path, TOKEN_OUT_FILE, TokenOp::Export).await {
                Ok(_) => {
                    info!("Fetching key file by using token object.");
                    get_key_from_out_token(env_vars, cert_list).await?;
                }
                Err(_) => {
                    error!("Can't re-run apps which are converted without filesystem persistence enabled. Filesystem persistence is set to {}", conv_use_dsm_key);
                    return Err(format!(
                        "Can't re-run apps which are converted without filesystem persistence enabled"
                    ));
                }
            }
            Ok(false)
        }
        Err(_) => {
            info!("Device is not a valid luks2 device. ");
            let passkey = generate_volume_passkey().await?;

            info!("Formatting RW device with new keyfile.");
            luks_format_device(key_path, NBD_RW_DEVICE).await?;

            // Use DSM for overlayfs persistance blockfile encryption.
            if conv_use_dsm_key {
                info!("Accessing DSM to store passkey in luks2 token");
                let enc_resp = dsm_enc_with_overlayfs_key(cert_list, env_vars, passkey)?;
                create_luks2_token_input(TOKEN_IN_FILE, env_vars, enc_resp)?;

                info!("Adding token object to the RW device");
                update_luks_token(device_path, TOKEN_IN_FILE, TokenOp::Import).await?;
            }
            Ok(true)
        }
    }
}

/// Generate the luks2 token object and write the same to
/// the json file which will be used to add a luks2 header
/// to the RW blockfile
fn create_luks2_token_input(token_path: &str, env_vars: &[(String, String)], enc_resp: EncryptResponse) -> Result<(), String> {
    info!("Creating Luks2 token object");
    let iv = enc_resp
        .iv
        .ok_or_else(|| format!("Unable to find IV from encrypt response"))?;

    let tag = enc_resp
        .tag
        .ok_or_else(|| format!("Unable to find tag from encrypt response"))?;

    let token_object = LuksToken {
        token_type: "Fortanix-sealing-key".to_string(),
        key_slots: vec!["0".to_string()],
        endpoint: find_env_or_err("FS_DSM_ENDPOINT", env_vars).unwrap_or(DEFAULT_DSM_ENDPOINT.to_string()),
        isvsvn: None,
        tag,
        enc_key: enc_resp.cipher,
        iv,
    };

    let token_string =
        serde_json::to_string(&token_object).map_err(|err| format!("Unable to convert token object to string : {:?}", err))?;

    info!("Writing luks2 token to file >> {:?}", token_string);
    let mut token_file = File::create(token_path).map_err(|err| format!("Unable to create token input file : {:?}", err))?;
    token_file
        .write_all(&*token_string.into_bytes())
        .map_err(|err| format!("Unable to write to token object: {:?}", err))?;

    Ok(())
}

pub(crate) async fn mount_read_write_file_system(
    env_vars: &[(String, String)],
    cert_list: Option<&mut CertificateResult>,
    enable_overlayfs_persistence: bool,
) -> Result<(), String> {
    // Create dir to get rid of the warning that is printed to the console by cryptsetup
    fs::create_dir_all(DM_CRYPT_FOLDER)
        .map_err(|err| format!("Failed to create folder {} for cryptsetup path. {:?}", DM_CRYPT_FOLDER, err))?;

    let create_ext4 = get_key_file(env_vars, cert_list, enable_overlayfs_persistence).await?;

    let crypt_setup_args: [&str; 7] = [
        "open",
        "--key-file",
        CRYPT_KEYFILE,
        "--type",
        "luks2",
        NBD_RW_DEVICE,
        DM_CRYPT_DEVICE,
    ];

    run_subprocess("cryptsetup", &crypt_setup_args).await?;

    let dm_crypt_mapped_device = DEVICE_MAPPER.to_string() + DM_CRYPT_DEVICE;

    if create_ext4 {
        info!("First use of RW device, creating an ext4 fs");
        run_subprocess("mkfs.ext4", &[&dm_crypt_mapped_device]).await?;
    }

    run_mount(&[&dm_crypt_mapped_device, ENCLAVE_FS_RW_ROOT]).await?;

    if create_ext4 {
        create_overlay_rw_dirs()?;
    }
    Ok(())
}

use shared::models::SetupMessages;
use shared::socket::AsyncWriteLvStream;
use tokio_vsock::VsockStream as AsyncVsockStream;

pub(crate) async fn check_available_encrypted_space(parent_port: &mut AsyncVsockStream) -> Result<(), String> {
    use sysinfo::{DiskExt, System, SystemExt};

    let mut s = System::new();
    s.refresh_disks_list();
    for disk in s.disks() {
        info!(
            "{:?} total space = {}B free space = {}B",
            disk.name(),
            disk.total_space(),
            disk.available_space()
        );
        if disk.name() == Path::new("/dev/mapper/").join(DM_CRYPT_DEVICE) {
            parent_port
                .write_lv(&SetupMessages::EncryptedSpaceAvailable(disk.available_space() as usize))
                .await?;
        }
    }
    Ok(())
}

pub(crate) async fn mount_overlay_fs() -> Result<(), String> {
    let overlay_dir_config = format!(
        "lowerdir={},upperdir={},workdir={}",
        ENCLAVE_FS_LOWER, ENCLAVE_FS_UPPER, ENCLAVE_FS_WORK
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
    info!("Creating work and upper layers....");
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

pub(crate) async fn unmount_file_system_nodes(nodes: &[FileSystemNode]) -> Result<(), String> {
    for node in nodes {
        match node {
            FileSystemNode::Proc => {
                run_unmount(&[&format!("{}/proc/", ENCLAVE_FS_OVERLAY_ROOT)]).await?;
            }
            FileSystemNode::TreeNode(node_path) => {
                run_unmount(&[
                    "-R",
                    &format!("{}{node_path}", ENCLAVE_FS_OVERLAY_ROOT, node_path = node_path),
                ])
                .await?;
            }
            FileSystemNode::File(file_path) => {
                run_unmount(&[&format!("{}{file_path}", ENCLAVE_FS_OVERLAY_ROOT, file_path = file_path)]).await?;
            }
        }
    }

    Ok(())
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

async fn generate_volume_passkey() -> Result<Blob, String> {
    // Create keyfile
    let key_blob = generate_keyfile()?;

    // Return key material as a blob
    Ok(Blob::from(key_blob))
}

pub(crate) fn find_env_or_err(key: &str, env_vars: &[(String, String)]) -> Result<String, String> {
    env_vars
        .iter()
        .find_map(|e| if e.0 == key { Some(e.1.clone()) } else { None })
        .ok_or(format!("{:?} is missing!", key))
}
