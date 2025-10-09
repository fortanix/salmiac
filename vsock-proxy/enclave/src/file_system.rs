/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::convert::TryInto;
use std::mem;
use std::net::IpAddr;
use std::path::Path;

use log::info;
use nix::sys::statvfs::FsFlags;
use rand::{thread_rng, Rng};
use sdkms::api_model::Blob;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use shared::{run_subprocess, run_subprocess_with_output_setup, CommandOutputConfig};
use tokio::fs;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

use crate::certificate::DEFAULT_CERT_DIR;
use crate::dsm_key_config::{ClientConnectionInfo, DsmFsOps, EncryptedPassphrase};

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

const DETACHED_HEADER_PATH: &str = "/tmp/detached-header";
const ENCRYPTED_DATA_OFFSET: usize = 18 * 1024 * 1024; // 18MB
const ENCRYPTED_DATA_OFFSET_IN_SECTORS: usize = ENCRYPTED_DATA_OFFSET / 512;
const LUKS_HDR_METADATA_SIZE: usize = 16 * 1024; // 16kB
const LUKS_HDR_KEYSLOT_SIZE: usize = 15 * 1024 * 1024; // 15MB
const HMAC_DIGEST_SIZE: usize = 32; // 32 bytes
const SIZEOF_USIZE: usize = mem::size_of::<usize>();
const SIZEOF_U16: usize = mem::size_of::<u16>();
const SALM_HDR_SIZE: usize = SIZEOF_U16 + SIZEOF_USIZE + HMAC_DIGEST_SIZE;
const SALM_HDR_OFFSET: usize = ENCRYPTED_DATA_OFFSET - SALM_HDR_SIZE;
const SALM_HDR_VERSION: u16 = 1;

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

#[derive(Clone)]
struct HeaderComponents {
    luks2_header: Blob,
    salm_header: SalmiacHeader,
}

#[derive(Clone)]
struct SalmiacHeader {
    luks_mac: Vec<u8>,
    luks_header_size: usize,
    version: u16,
}

impl HeaderComponents {
    /*
     * This describes the format of the encrypted file that is managed by Salmiac to provide the read-write overlay of the guest filesystem.
     * The LUKS 2 header format can be referred to here - https://gitlab.com/cryptsetup/LUKS2-docs/blob/main/luks2_doc_wip.pdf
     * Metadata for obtaining the passphrase of the encrypted file is stored in the form of a 'LuksToken' in the LUKS2 header.
     *
     * To protect against certain attacks (as described in RTE-537), the salmiac header is introduced.
     * The salmiac header contains a version number, the size and HMAC of the LUKS2 header.
     * -----------------------------------------------------------------------------------------------------------------------------------------------------------
     * |                  LUKS2 header                 |              |                     Salmiac header                                   |                   |
     * |                                               | -->       <--|                                                                      |   Encrypted data  |
     * |  binary header  |  metadata  |  keyslot area  |              |  luks2 header HMAC  |  luks2 header size  |  salmiac header version  |                   |
     * -----------------------------------------------------------------------------------------------------------------------------------------------------------
     * <-----------------------------------------------ENCRYPTED_DATA_OFFSET----------------------------------------------------------------->
     *                                                                  <------------------------SALM_HDR_SIZE------------------------------->
     */

    // Given the path to a device, read HeaderComponents from the start of the device
    pub async fn parse_from(device_path: &str) -> Result<Self, String> {
        // Read the whole offset area into a buffer - this includes the luks header, salmiac header and the empty space between them
        let hdr_comp_buf = Self::copy_data_out_of_device(device_path, 0, ENCRYPTED_DATA_OFFSET).await?;
        if hdr_comp_buf.len() < ENCRYPTED_DATA_OFFSET {
            return Err(format!(
                "The file buffer obtained is too small to obtain HeaderComponents from : {:?}",
                hdr_comp_buf.len()
            ));
        }

        // Read the salmiac header from the buffer
        let version_buf: [u8; SIZEOF_U16] = hdr_comp_buf[ENCRYPTED_DATA_OFFSET - SIZEOF_U16..ENCRYPTED_DATA_OFFSET]
            .try_into()
            .map_err(|e| format!("Version buffer size unexpected {:?}", e))?;
        let version = u16::from_ne_bytes(version_buf);
        if version != SALM_HDR_VERSION {
            return Err(format!("Unexpected salmiac header version {:?}", version));
        }

        let luks_header_size_buf: [u8; SIZEOF_USIZE] = hdr_comp_buf
            [ENCRYPTED_DATA_OFFSET - SIZEOF_U16 - SIZEOF_USIZE..ENCRYPTED_DATA_OFFSET - SIZEOF_U16]
            .try_into()
            .map_err(|e| format!("luks header size buffer size unexpected {:?}", e))?;
        let luks_header_size = usize::from_ne_bytes(luks_header_size_buf);
        if (luks_header_size < (LUKS_HDR_KEYSLOT_SIZE + LUKS_HDR_METADATA_SIZE)) || (luks_header_size > ENCRYPTED_DATA_OFFSET) {
            return Err(format!("Unexpected luks header size {:?}", luks_header_size));
        }

        let luks_mac = hdr_comp_buf[ENCRYPTED_DATA_OFFSET - SIZEOF_U16 - SIZEOF_USIZE - HMAC_DIGEST_SIZE
            ..ENCRYPTED_DATA_OFFSET - SIZEOF_U16 - SIZEOF_USIZE]
            .to_vec();
        let salm_header = SalmiacHeader {
            version,
            luks_header_size,
            luks_mac,
        };

        // Read the luks2 header from the buffer
        let luks2_header = Blob::from(hdr_comp_buf[0..luks_header_size].to_vec());

        Ok(HeaderComponents {
            luks2_header,
            salm_header,
        })
    }

    // For a given HeaderComponents data, verify if the HMAC of the header checks out
    pub async fn verify_header(&self, dsm_fs: &DsmFsOps) -> Result<(), String> {
        // Generate a sha256 hash of the luks2 header
        let mut hasher = Sha256::new();
        hasher.update(&self.luks2_header);
        let header_hash = hasher.finalize();

        // Verify the HMAC of the header hash
        dsm_fs
            .dsm_mac_verify_header(Blob::from(header_hash.to_vec()), self.salm_header.luks_mac.clone().into())
            .await
    }

    // Write a given HeaderComponents data into the device keeping the above described
    // format in mind. It is upto the caller to ensure that the luks2 header mac is
    // computed/verified before calling this function.
    pub async fn write_to(self, dst_device_path: &str) -> Result<(), String> {
        // Write the luks2 header first
        Self::copy_data_to_device_offset(dst_device_path, 0, &self.luks2_header.to_vec()).await?;

        // Construct the salmiac header in a buffer
        let mut salm_hdr_buf = [0; SALM_HDR_SIZE];
        salm_hdr_buf[0..HMAC_DIGEST_SIZE].copy_from_slice(&self.salm_header.luks_mac);
        salm_hdr_buf[HMAC_DIGEST_SIZE..HMAC_DIGEST_SIZE + SIZEOF_USIZE]
            .copy_from_slice(&self.salm_header.luks_header_size.to_ne_bytes());
        salm_hdr_buf[HMAC_DIGEST_SIZE + SIZEOF_USIZE..].copy_from_slice(&self.salm_header.version.to_ne_bytes());

        // Copy the salmiac header at its specific offset
        Self::copy_data_to_device_offset(dst_device_path, SALM_HDR_OFFSET, &salm_hdr_buf.to_vec()).await?;
        Ok(())
    }

    // Given the path of a detached luks2 header, obtain the HeaderComponents data
    pub async fn create_hdr_comp(luks_hdr_path: &str, dsm_fs: Option<&DsmFsOps>) -> Result<HeaderComponents, String> {
        // Read the luks2 header from the detached header path
        let luks2_header = fs::read(luks_hdr_path)
            .await
            .map_err(|e| format!("Unable to read detached header {:?} : {:?}", luks_hdr_path, e))?;
        let luks_header_size = luks2_header.len();

        // If a dsm client is provided, obtain the HMAC of the header
        let luks_mac = match dsm_fs {
            None => vec![0; HMAC_DIGEST_SIZE],
            Some(dsm_fs_local) => {
                // Generate a sha256 hash of the luks2 header
                let mut hasher = Sha256::new();
                hasher.update(&luks2_header);
                let header_hash = hasher.finalize();

                // Get the HMAC of the header hash
                let mac = dsm_fs_local.dsm_mac_header(Blob::from(header_hash.to_vec())).await?;
                mac.into()
            }
        };

        let salm_header = SalmiacHeader {
            version: SALM_HDR_VERSION,
            luks_header_size,
            luks_mac: luks_mac.to_vec(),
        };

        Ok(HeaderComponents {
            luks2_header: luks2_header.into(),
            salm_header,
        })
    }

    // Create a LUKS2 detached header for a given HeaderComponents data
    pub async fn create_detached_header(self, header_path: &str) -> Result<(), String> {
        fs::write(header_path, &self.luks2_header)
            .await
            .map_err(|e| format!("Failed to write to header at {:?} : {:?}", header_path, e))?;
        Ok(())
    }
    async fn copy_data_to_device_offset(device_path: &str, offset: usize, source: &Vec<u8>) -> Result<(), String> {
        let mut device_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)
            .await
            .map_err(|e| format!("Unable to open device path : {:?}", e))?;

        device_file
            .seek(SeekFrom::Start(offset as u64))
            .await
            .map_err(|e| e.to_string())?;

        device_file.write_all(&source).await.map_err(|e| e.to_string())?;
        device_file
            .shutdown()
            .await
            .map_err(|e| format!("Error while flushing device file write : {:?}", e))?;

        Ok(())
    }

    async fn copy_data_out_of_device(device_path: &str, offset: usize, size: usize) -> Result<Vec<u8>, String> {
        let mut device_file = File::open(device_path)
            .await
            .map_err(|e| format!("Unable to open device file {:?} to copy data out : {:?}", device_path, e))?;

        device_file
            .seek(SeekFrom::Start(offset as u64))
            .await
            .map_err(|e| format!("Seek to offset {:?} failed for {:?} : {:?}", offset, device_path, e))?;

        let mut temp_buf = vec![0u8; size];
        device_file
            .read_exact(&mut temp_buf)
            .await
            .map_err(|e| format!("Read exact {:?} bytes from {:?} failed : {:?}", size, device_path, e))?;

        Ok(temp_buf)
    }
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
                if *node_path == "/tmp" && mount_options.is_tmp_exec {
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

pub(crate) async fn generate_keyfile() -> Result<Vec<u8>, String> {
    // Generate key material from random data generator
    let mut arr = vec![0u8; CRYPT_KEYSIZE];
    thread_rng()
        .try_fill(&mut arr[..])
        .map_err(|err| format!("Unable to fill key buffer with random data : {:?}", err))?;

    // Write the key contents to the keyfile
    let _key_file = fs::write(CRYPT_KEYFILE, &*arr.clone())
        .await
        .map_err(|err| format!("Unable to write to key file : {:?}", err))?;

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
async fn luks_format_device(key_path: &Path, device_path: &str, header_path: &str) -> Result<(), String> {
    let key_path_as_str = key_path
        .to_str()
        .ok_or(format!("Failed converting path {} to string", key_path.display()))?;

    let luks_format_args = [
        "luksFormat",
        "-q",
        "--luks2-metadata-size",
        &LUKS_HDR_METADATA_SIZE.to_string(),
        "--luks2-keyslots-size",
        &LUKS_HDR_KEYSLOT_SIZE.to_string(),
        "--type",
        "luks2",
        "--offset",
        &ENCRYPTED_DATA_OFFSET_IN_SECTORS.to_string(),
        "--header",
        header_path,
        device_path,
        key_path_as_str,
    ];
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
async fn update_luks_token(header_path: &str, token_path: &str, op: TokenOp) -> Result<(), String> {
    let op_str = if op == TokenOp::Import { "import" } else { "export" };

    info!(
        "{:?} token for device header {:?} at {:?}",
        &op_str, &header_path, &token_path
    );
    let token_args = ["token", op_str, "--token-id", "0", "--json-file", token_path, header_path];
    run_subprocess("cryptsetup", &token_args).await
}

/// Opens the output token file. Parses it into a luks2 token object.
/// After parsing the token to obtain parameters needed to access DSM,
/// fetch the overlay fs key used to wrap the RW volume passkey.
async fn get_key_from_out_token(dsm_fs: &DsmFsOps) -> Result<(), String> {
    // Open and parse the dmcrypt volume token file
    let token_contents = fs::read(TOKEN_OUT_FILE)
        .await
        .map_err(|err| format!("Unable to open token out file : {:?}", err))?;

    info!(
        "Token contents are >> {:?} : {:?}",
        std::str::from_utf8(&token_contents.clone()).map_err(|e| format!("Unable to convert token contents to utf8 : {:?}", e)),
        token_contents.len()
    );

    let token_json_obj: LuksToken = serde_json::from_slice(&token_contents)
        .map_err(|err| format!("Unable to decode Token json object from slice : {:?}", err))?;

    let enc_key = EncryptedPassphrase {
        key: token_json_obj.enc_key,
        iv: token_json_obj.iv,
        tag: token_json_obj.tag,
    };

    // Fetch the decrypted volume passkey
    let dec_resp = dsm_fs.dsm_decrypt_passphrase(enc_key).await?;

    // Create the key file
    let key_contents: Vec<u8> = dec_resp.into();
    let _key_file = fs::write(CRYPT_KEYFILE, &key_contents)
        .await
        .map_err(|err| format!("Unable to write to key file : {:?}", err))?;

    info!("Key file created.");

    Ok(())
}

/// Generates the passkey file used to encrypt the RW block device
/// Returns a boolean value to indicate whether it is the first run
/// of the app or not. When it is the first run of the app, the caller
/// of this function creates a ext4 filesystem on it after opening
/// the device
async fn get_key_file(conn_info: Option<ClientConnectionInfo<'_>>) -> Result<bool, String> {
    let device_path = NBD_RW_DEVICE;
    let key_path = Path::new(CRYPT_KEYFILE);
    let mut conv_use_dsm_key = false;

    if conn_info.is_some() {
        conv_use_dsm_key = true;
    }

    match is_luks_device(device_path).await {
        Ok(_) => {
            info!("Luks2 device found. Attempting to fetch luks2 header and token.");

            if conv_use_dsm_key {
                let conn_info_l = conn_info.ok_or("expected connection info to obtain metadata")?;
                let dsm_fs = DsmFsOps::new(conn_info_l)?;

                let hdr_comp = HeaderComponents::parse_from(NBD_RW_DEVICE).await?;
                hdr_comp.verify_header(&dsm_fs).await?;

                hdr_comp.create_detached_header(DETACHED_HEADER_PATH).await?;

                if let Ok(_) = update_luks_token(DETACHED_HEADER_PATH, TOKEN_OUT_FILE, TokenOp::Export).await {
                    info!("Fetching key file by using token object.");
                    get_key_from_out_token(&dsm_fs).await?;
                } else {
                    return Err(format!("Can't re-run apps which are converted without filesystem persistence enabled. Filesystem persistence is set to {}", conv_use_dsm_key));
                }
            } else {
                return Err(format!("Can't re-run apps which are converted without filesystem persistence enabled. Filesystem persistence is set to {}", conv_use_dsm_key));
            }
            Ok(false)
        }
        Err(_) => {
            info!("Device is not a valid luks2 device. ");
            let passkey = generate_volume_passkey().await?;

            info!("Formatting RW device with new keyfile.");
            luks_format_device(key_path, NBD_RW_DEVICE, DETACHED_HEADER_PATH).await?;

            // Use DSM for overlayfs persistance blockfile encryption.
            if conv_use_dsm_key {
                info!("Accessing DSM to store passkey in luks2 token");
                let conn_info_l = conn_info.ok_or("expected connection info to save metadata")?;
                let dsm_url = conn_info_l.dsm_url.clone();
                let dsm_fs = DsmFsOps::new(conn_info_l)?;

                let enc_resp = dsm_fs.dsm_encrypt_passphrase(passkey.clone()).await?;
                create_luks2_token_input(TOKEN_IN_FILE, &dsm_url, enc_resp).await?;

                info!("Adding token object to the RW device");
                update_luks_token(DETACHED_HEADER_PATH, TOKEN_IN_FILE, TokenOp::Import).await?;

                let hdr_comp = HeaderComponents::create_hdr_comp(DETACHED_HEADER_PATH, Some(&dsm_fs)).await?;
                hdr_comp.write_to(NBD_RW_DEVICE).await?;
            } else {
                info!("Skipping the step to create and write the luks and salmiac header to device - Filesystem persistence is set to {}", conv_use_dsm_key);
            }
            Ok(true)
        }
    }
}

/// Generate the luks2 token object and write the same to
/// the json file which will be used to add a luks2 header
/// to the RW blockfile
async fn create_luks2_token_input(token_path: &str, dsm_url: &String, enc_resp: EncryptedPassphrase) -> Result<(), String> {
    info!("Creating Luks2 token object");

    let token_object = LuksToken {
        token_type: "Fortanix-sealing-key".to_string(),
        key_slots: vec!["0".to_string()],
        endpoint: dsm_url.into(),
        isvsvn: None,
        tag: enc_resp.tag,
        enc_key: enc_resp.key,
        iv: enc_resp.iv,
    };

    let token_string =
        serde_json::to_string(&token_object).map_err(|err| format!("Unable to convert token object to string : {:?}", err))?;

    info!("Writing luks2 token to file >> {:?}", token_string);
    let _token_file = fs::write(token_path, &*token_string.into_bytes())
        .await
        .map_err(|err| format!("Unable to write token input file : {:?}", err))?;

    Ok(())
}

pub(crate) async fn mount_read_write_file_system(conn_info: Option<ClientConnectionInfo<'_>>) -> Result<(), String> {
    // Create dir to get rid of the warning that is printed to the console by cryptsetup
    fs::create_dir_all(DM_CRYPT_FOLDER)
        .await
        .map_err(|err| format!("Failed to create folder {} for cryptsetup path. {:?}", DM_CRYPT_FOLDER, err))?;

    let create_ext4 = get_key_file(conn_info).await?;

    let crypt_setup_args: [&str; 9] = [
        "open",
        "--key-file",
        CRYPT_KEYFILE,
        "--type",
        "luks2",
        "--header",
        DETACHED_HEADER_PATH,
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
        create_overlay_rw_dirs().await?;
    }
    Ok(())
}

pub(crate) async fn get_available_encrypted_space() -> Result<usize, String> {
    use sysinfo::{DiskExt, System, SystemExt};

    let mut system = System::new();
    system.refresh_disks_list();
    for disk in system.disks() {
        info!(
            "{:?} total space = {}B free space = {}B",
            disk.name(),
            disk.total_space(),
            disk.available_space()
        );
        if disk.name() == Path::new("/dev/mapper/").join(DM_CRYPT_DEVICE) {
            return Ok(disk.available_space() as usize);
        }
    }
    Ok(0)
}

pub(crate) async fn mount_overlay_fs() -> Result<(), String> {
    let overlay_dir_config = format!(
        "lowerdir={},upperdir={},workdir={}",
        ENCLAVE_FS_LOWER, ENCLAVE_FS_UPPER, ENCLAVE_FS_WORK
    );

    run_mount(&["-t", "overlay", "-o", &overlay_dir_config, "none", ENCLAVE_FS_OVERLAY_ROOT]).await
}

pub(crate) async fn create_overlay_dirs() -> Result<(), String> {
    fs::create_dir(ENCLAVE_FS_LOWER)
        .await
        .map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_LOWER, err))?;
    fs::create_dir(ENCLAVE_FS_RW_ROOT)
        .await
        .map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_UPPER, err))?;
    fs::create_dir(ENCLAVE_FS_OVERLAY_ROOT)
        .await
        .map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_OVERLAY_ROOT, err))?;

    Ok(())
}

pub(crate) async fn create_overlay_rw_dirs() -> Result<(), String> {
    info!("Creating work and upper layers....");
    fs::create_dir(ENCLAVE_FS_WORK)
        .await
        .map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_WORK, err))?;
    fs::create_dir(ENCLAVE_FS_UPPER)
        .await
        .map_err(|err| format!("Failed to create dir {}. {:?}", ENCLAVE_FS_UPPER, err))?;

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

pub(crate) async fn copy_startup_binary_to_mount(startup_binary: &str) -> Result<(), String> {
    const STARTUP_PATH: &str = "/opt/fortanix/enclave-os";

    let from = STARTUP_PATH.to_string() + startup_binary;
    let to = ENCLAVE_FS_OVERLAY_ROOT.to_string() + startup_binary;

    fs::copy(&from, &to)
        .await
        .map_err(|err| format!("Failed to copy enclave startup binary from {} to {}. {:?}", from, to, err))?;

    Ok(())
}

pub(crate) async fn create_fortanix_directories() -> Result<(), String> {
    let dir = Path::new(ENCLAVE_FS_OVERLAY_ROOT).join(DEFAULT_CERT_DIR.strip_prefix("/").unwrap_or_default());
    fs::create_dir_all(dir.clone())
        .await
        .map_err(|e| format!("Failed to create fortanix directory {:?} : {:?}", dir, e))
}

pub(crate) async fn copy_dns_file_to_mount() -> Result<(), String> {
    const ENCLAVE_RUN_RESOLV_FILE: &str = "/run/resolvconf/resolv.conf";

    let nbd_run_resolv_dir: &str = &format!("{}/run/resolvconf", ENCLAVE_FS_OVERLAY_ROOT);

    let nbd_etc_dir: &str = &format!("{}/etc", ENCLAVE_FS_OVERLAY_ROOT);

    let nbd_run_resolv_file: &str = &format!("{}/run/resolvconf/resolv.conf", ENCLAVE_FS_OVERLAY_ROOT);

    let nbd_etc_resolv_file: &str = &format!("{}/etc/resolv.conf", ENCLAVE_FS_OVERLAY_ROOT);

    fs::create_dir_all(nbd_run_resolv_dir)
        .await
        .map_err(|err| format!("Failed creating {} dir. {:?}", nbd_run_resolv_dir, err))?;
    fs::create_dir_all(nbd_etc_dir)
        .await
        .map_err(|err| format!("Failed creating {} dir. {:?}", nbd_etc_dir, err))?;

    // We copy resolv.conf from the enclave kernel into the block file mount point
    // so that DNS will work correctly after we do a `chroot`.
    // Using `/usr/bin/mount` to accomplish the same task doesn't seem to work.
    fs::copy(ENCLAVE_RUN_RESOLV_FILE, nbd_run_resolv_file).await.map_err(|err| {
        format!(
            "Failed copying resolv file from {} to {}. {:?}",
            ENCLAVE_RUN_RESOLV_FILE, nbd_run_resolv_file, err
        )
    })?;
    fs::copy(ENCLAVE_RUN_RESOLV_FILE, nbd_etc_resolv_file).await.map_err(|err| {
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
    let key_blob = generate_keyfile().await?;

    // Return key material as a blob
    Ok(Blob::from(key_blob))
}
