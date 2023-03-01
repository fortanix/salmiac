use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::Path;

use log::info;
use sdkms::api_model::{Sobject, SobjectDescriptor};
use sdkms::SdkmsClient;
use shared::run_subprocess;

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
const CRYPT_KEYFILE: &str = "/etc/rw-keyfile";
const TOKEN_IN_FILE: &str = "/etc/token-in.json";
const TOKEN_OUT_FILE: &str = "/etc/token-out.json";
const TMP_TOKEN_IN: &str = r#"{"type":"fortanix-virtual-sealing-key","keyslots":["0"],
"plugin_url":"https://api.amer.smartkey.io/sys/v1/plugins/00000000-0000-0000-0000-000000000000",
"app_id":"00000000-0000-0000-0000-000000000000","key_id":"00000000-0000-0000-0000-000000000000",
"security_version":"?"}"#;
const TMP_TOKEN_SIZE: usize = TMP_TOKEN_IN.len();

#[derive(PartialEq)]
enum TokenOp {
    Export,
    Import,
}

pub (crate) enum FileSystemNode {
    Proc,
    TreeNode(&'static str),
    File(&'static str)
}

pub(crate) async fn mount_file_system_nodes(nodes: &[FileSystemNode]) -> Result<(), String> {
    for node in nodes {
        match node {
            FileSystemNode::Proc => {
                run_mount(&["-t", "proc", "/proc", &format!("{}/proc/", ENCLAVE_FS_OVERLAY_ROOT)]).await?;
            }
            FileSystemNode::TreeNode(node_path) => {
                run_mount(&["--rbind", node_path, &format!("{}{node_path}", ENCLAVE_FS_OVERLAY_ROOT, node_path=node_path)]).await?;
            }
            FileSystemNode::File(file_path) => {
                run_mount(&["--bind", file_path, &format!("{}{file_path}", ENCLAVE_FS_OVERLAY_ROOT, file_path=file_path)]).await?;
            }
        }
    }

    Ok(())
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

/// Check if the device is a valid crypt luks device
/// Passing --type specifically checks for the version of luks used
/// -v option provides a verbose output rather than returning 0 or 1
/// for success or failure
async fn is_luks_device(device_path: &str) -> Result<(), String> {
    let args = ["isLuks", "--type", "luks2", "-v", device_path];
    run_subprocess("cryptsetup", &args).await
}

async fn update_luks_token(device_path: &str, token_path: &str, op: TokenOp) -> Result<(), String> {
    let op_str = if op == TokenOp::Import { "import" } else { "export" };

    info!("{:?} token for device {:?} at {:?}", &op_str, &device_path, &token_path);
    let token_args = ["token", op_str, "--token-id", "0", "--json-file", token_path, device_path];
    run_subprocess("cryptsetup", &token_args).await
}

async fn get_key_from_token(token_path: &str, key_path: &Path, env_vars: &[(String, String)]) -> Result<(), String> {
    let token_file = fs::File::open(token_path).map_err(|err| format!("Unable to open file {:?} : {:?}", token_path, err));
    let mut token_contents = [0; TMP_TOKEN_SIZE];
    token_file?
        .read(&mut token_contents)
        .map_err(|err| format!("Unable to read from token file {:?} : {:?}", token_path, err))?;

    // TODO: Use token contents to fetch VSK once we know what goes into the token
    let token_data =
        std::str::from_utf8(&token_contents).map_err(|err| format!("Unable to read utf8 string from token file : {:?}", err));
    info!(
        "Token contents are >> {:?}",
        token_data.map_err(|err| format!("Unable to print token contents : {:?}", err))
    );

    let key_file = fs::File::create(key_path).map_err(|err| format!("Unable to create key file {:?} : {:?}", key_path, err));
    let vsk_obj = request_vsk(env_vars)?;
    let vsk_val = vsk_obj.value.expect("Sobject does not contain a sealing key");
    // TODO: Use the vsk to encrypt a randomly generated key using AES_GCM which
    // would be stored in the luks token object
    key_file?
        .write(&vsk_val)
        .map_err(|err| format!("Unable to write to key file: {:?}", err))?;

    info!("Key file created...");

    Ok(())
}

async fn get_key_file(device_path: &str, key_path: &Path, env_vars: &[(String, String)]) -> Result<bool, String> {
    let use_vsk = env_vars
        .iter()
        .find_map(|e| {
            if e.0 == "USE_VSK" && (e.1.trim() == "true" || e.1 == "1" || e.1 == "True") {
                Some(true)
            } else {
                None
            }
        })
        .unwrap_or(false);

    match is_luks_device(device_path).await {
        Ok(_) => {
            info!("Luks2 device found. Fetching luks2 token.");
            update_luks_token(device_path, TOKEN_OUT_FILE, TokenOp::Export).await?;

            info!("Fetching key file by using token object.");
            get_key_from_token(TOKEN_OUT_FILE, key_path, env_vars).await?;
            Ok(false)
        }
        Err(_) => {
            info!("Device is not a valid luks2 device. ");
            if !use_vsk {
                info!("Skipping usage of vsk, generating a random key file");
                generate_keyfile(key_path).await?;
            } else {
                info!("Fetching vsk");
                // TODO: Remove next 2 lines of code. For now, this creates a dummy token input file
                // TBD: JSON format of the token file to be created
                let mut key_file =
                    fs::File::create(TOKEN_IN_FILE).map_err(|err| format!("Unable to open token in file : {:?}", err))?;
                key_file
                    .write(TMP_TOKEN_IN.as_bytes())
                    .map_err(|err| format!("Unable to open write in token in file : {:?}", err))?;
                get_key_from_token(TOKEN_IN_FILE, key_path, env_vars).await?;
            }
            info!("Formatting RW device with new keyfile.");
            luks_format_device(key_path, NBD_RW_DEVICE).await?;

            if use_vsk {
                info!("Adding token object to the RW device");
                update_luks_token(device_path, TOKEN_IN_FILE, TokenOp::Import).await?;
            }
            Ok(true)
        }
    }
}

pub(crate) async fn mount_read_write_file_system(env_vars: &[(String, String)]) -> Result<(), String> {
    let create_ext4 = get_key_file(NBD_RW_DEVICE, Path::new(CRYPT_KEYFILE), env_vars).await?;

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
                run_unmount(&["-R", &format!("{}{node_path}", ENCLAVE_FS_OVERLAY_ROOT, node_path=node_path)]).await?;
            }
            FileSystemNode::File(file_path) => {
                run_unmount(&[&format!("{}{file_path}", ENCLAVE_FS_OVERLAY_ROOT, file_path=file_path)]).await?;
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
fn find_env_or_err(key: &str, env_vars: &[(String, String)]) -> Result<String, String> {
    env_vars
        .iter()
        .find_map(|e| if e.0 == key { Some(e.1.clone()) } else { None })
        .ok_or(format!("{:?} is missing!", key))
}

pub(crate) fn request_vsk(env_vars: &[(String, String)]) -> Result<Sobject, String> {
    let key_name = find_env_or_err("FS_KEY_NAME", env_vars)?;
    let api_key = find_env_or_err("FS_API_KEY", env_vars)?;
    let vsk_endpoint = find_env_or_err("FS_VSK_ENDPOINT", env_vars)?;

    info!(
        "Creating sdkms client with endpoint {:?} and api key {:?}",
        vsk_endpoint, api_key
    );
    let client = SdkmsClient::builder()
        .with_api_endpoint(&vsk_endpoint)
        .with_api_key(&api_key)
        .build()
        .map_err(|err| {
            format!(
                "Failed building SDKMS API client with endpoint {:?} : {:?}",
                vsk_endpoint, err
            )
        })?;

    let version = client.version().map_err(|e| format!("Unable to connect to sdkms client {:?}", e))?;
    info!("Connected to sdkms version {} API version {}", version.version, version.api_version);

    let request = SobjectDescriptor::Name(key_name.clone());
    info!("Requesting key with name {:?}", key_name);
    client
        .export_sobject(&request)
        .map_err(|err| format!("Failed requesting VSK {}. {:?}", key_name, err))
}
