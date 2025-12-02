/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod dsm_key_config;
pub mod error;
pub mod utils;

use std::convert::TryInto;
use std::mem;
use std::path::Path;

use log::info;
use rand::{thread_rng, Rng};
use sdkms::api_model::Blob;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

use crate::dsm_key_config::{DsmInterface, EncryptedPassphrase};
use crate::utils::{run_fsck, run_subprocess, run_subprocess_with_output_setup, CommandOutputConfig};
const DM_CRYPT_DEVICE: &str = "cryptdevice";
const DM_CRYPT_FOLDER: &str = "/run/cryptsetup";
const CRYPT_KEYFILE: &str = "/etc/rw-keyfile";
const CRYPT_KEYSIZE: usize = 512;
const TOKEN_IN_FILE: &str = "/etc/token-in.json";
const TOKEN_OUT_FILE: &str = "/etc/token-out.json";
pub const DEVICE_MAPPER: &str = "/dev/mapper/";

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

#[derive(PartialEq)]
enum TokenOp {
    Export,
    Import,
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
    pub async fn verify_header(&self, dsm_fs: &impl DsmInterface) -> Result<(), String> {
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
    pub async fn create_hdr_comp(luks_hdr_path: &str, dsm_fs: Option<&impl DsmInterface>) -> Result<HeaderComponents, String> {
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

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct EncryptedVolume {
    is_open: bool,
    is_mounted: bool,
    device_path: String,
    mount_path: String,
}

impl EncryptedVolume {
    pub fn init(device_path: &str, mount_path: &str) -> EncryptedVolume {
        EncryptedVolume {
            is_mounted: false,
            is_open: false,
            device_path: device_path.to_string(),
            mount_path: mount_path.to_string(),
        }
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
    async fn get_key_from_out_token(dsm_fs: &impl DsmInterface) -> Result<(), String> {
        // Open and parse the dmcrypt volume token file
        let token_contents = fs::read(TOKEN_OUT_FILE)
            .await
            .map_err(|err| format!("Unable to open token out file : {:?}", err))?;

        info!(
            "Token contents are >> {:?} : {:?}",
            std::str::from_utf8(&token_contents.clone())
                .map_err(|e| format!("Unable to convert token contents to utf8 : {:?}", e)),
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
    async fn setup_device(dsm_ops_handler: Option<impl DsmInterface>, device_path: &str) -> Result<bool, String> {
        let key_path = Path::new(CRYPT_KEYFILE);
        let mut conv_use_dsm_key = false;

        if dsm_ops_handler.is_some() {
            conv_use_dsm_key = true;
        }

        match Self::is_luks_device(device_path).await {
            Ok(_) => {
                info!("Luks2 device found. Attempting to fetch luks2 header and token.");

                if conv_use_dsm_key {
                    let dsm_fs = dsm_ops_handler.ok_or("expected dsm_ops_handler to obtain metadata")?;

                    let hdr_comp = HeaderComponents::parse_from(device_path).await?;
                    hdr_comp.verify_header(&dsm_fs).await?;

                    hdr_comp.create_detached_header(DETACHED_HEADER_PATH).await?;

                    if let Ok(_) = Self::update_luks_token(DETACHED_HEADER_PATH, TOKEN_OUT_FILE, TokenOp::Export).await {
                        info!("Fetching key file by using token object.");
                        Self::get_key_from_out_token(&dsm_fs).await?;
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
                let passkey = Self::generate_volume_passkey().await?;

                info!("Formatting RW device with new keyfile.");
                Self::luks_format_device(key_path, device_path, DETACHED_HEADER_PATH).await?;

                // Use DSM for overlayfs persistance blockfile encryption.
                if conv_use_dsm_key {
                    info!("Accessing DSM to store passkey in luks2 token");
                    let dsm_fs = dsm_ops_handler.ok_or("expected dsm_ops_handler to obtain metadata")?;
                    let dsm_url = dsm_fs.dsm_get_endpoint()?;

                    let enc_resp = dsm_fs.dsm_encrypt_passphrase(passkey.clone()).await?;
                    Self::create_luks2_token_input(TOKEN_IN_FILE, &dsm_url, enc_resp).await?;

                    info!("Adding token object to the RW device");
                    Self::update_luks_token(DETACHED_HEADER_PATH, TOKEN_IN_FILE, TokenOp::Import).await?;

                    let hdr_comp = HeaderComponents::create_hdr_comp(DETACHED_HEADER_PATH, Some(&dsm_fs)).await?;
                    hdr_comp.write_to(device_path).await?;
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

        let token_string = serde_json::to_string(&token_object)
            .map_err(|err| format!("Unable to convert token object to string : {:?}", err))?;

        info!("Writing luks2 token to file >> {:?}", token_string);
        let _token_file = fs::write(token_path, &*token_string.into_bytes())
            .await
            .map_err(|err| format!("Unable to write token input file : {:?}", err))?;

        Ok(())
    }

    pub async fn setup_encrypted_volume(
        dsm_ops_handler: Option<impl DsmInterface>,
        device_path: &str,
        mount_path: &str,
    ) -> Result<EncryptedVolume, String> {
        let mut result = EncryptedVolume::init(device_path, mount_path);
        // If the dmcrypt run folder doesn't exist it leads to a warning message on the console
        // for the same. This directory is needed by cryptsetup for locking operations. Ideally it is
        // created by systemd or tmpfiles.d. Create the directory if it is not already present.
        if !Path::new(DM_CRYPT_FOLDER).exists() {
            fs::create_dir_all(DM_CRYPT_FOLDER)
                .await
                .map_err(|err| format!("Failed to create folder {} for cryptsetup path. {:?}", DM_CRYPT_FOLDER, err))?;
        }

        // Check if the data disk/device path exists.
        if !Path::new(device_path).exists() {
            return Err(format!(
                "Unable to setup encrypted volume : {:?} device does not exist",
                device_path
            ));
        }

        // Either create a new key file or use the one in the luks header
        let is_first_run = Self::setup_device(dsm_ops_handler, device_path).await?;

        let crypt_setup_args: [&str; 9] = [
            "open",
            "--key-file",
            CRYPT_KEYFILE,
            "--type",
            "luks2",
            "--header",
            DETACHED_HEADER_PATH,
            device_path,
            DM_CRYPT_DEVICE,
        ];

        // Open the dmcrypt device
        run_subprocess("cryptsetup", &crypt_setup_args).await?;
        result.is_open = true;

        let dm_crypt_mapped_device = DEVICE_MAPPER.to_string() + DM_CRYPT_DEVICE;

        if is_first_run {
            info!("First use of RW device, creating an ext4 fs");
            run_subprocess("mkfs.ext4", &[&dm_crypt_mapped_device]).await?;
        }

        // Check if the mount path exists. If not, create it.
        if !Path::new(mount_path).exists() {
            fs::create_dir_all(Path::new(mount_path))
                .await
                .map_err(|e| format!("Unable to create {:?} mount dir : {:?}", mount_path, e))?;
        }

        // Mount the dmcrypt device to it's corresponding mount point
        run_fsck(&dm_crypt_mapped_device).await;
        Self::run_mount(&[&dm_crypt_mapped_device, mount_path]).await?;
        result.is_mounted = true;

        // Print the available encrypted space available
        Self::get_available_encrypted_space().await?;

        Ok(result)
    }

    pub async fn get_available_encrypted_space() -> Result<usize, String> {
        use sysinfo::{DiskExt, System, SystemExt};

        let mut system = System::new();
        system.refresh_disks_list();
        for disk in system.disks() {
            if disk.name() == Path::new("/dev/mapper/").join(DM_CRYPT_DEVICE) {
                info!(
                    "{:?} total space = {}B free space = {}B",
                    disk.name(),
                    disk.total_space(),
                    disk.available_space()
                );
                return Ok(disk.available_space() as usize);
            }
        }
        Ok(0)
    }

    async fn generate_volume_passkey() -> Result<Blob, String> {
        // Create keyfile
        let key_blob = Self::generate_keyfile().await?;

        // Return key material as a blob
        Ok(Blob::from(key_blob))
    }

    pub async fn cleanup_encrypted_volume(&self) -> Result<(), String> {
        run_subprocess("/usr/bin/umount", &[&self.mount_path]).await?;
        info!("Unmounted encrypted file system.");

        Self::close_dm_crypt_device().await?;
        info!("Closed dm-crypt device.");

        Ok(())
    }

    pub async fn close_dm_crypt_device() -> Result<(), String> {
        run_subprocess("cryptsetup", &["close", DM_CRYPT_DEVICE]).await
    }

    async fn run_mount(args: &[&str]) -> Result<(), String> {
        run_subprocess("/usr/bin/mount", args).await
    }
}
