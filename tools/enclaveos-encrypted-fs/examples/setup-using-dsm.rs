/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


use std::path::Path;

use enclaveos_encrypted_fs::dsm_key_config::{ClientConnectionInfo, DsmFsOps, DEFAULT_DSM_ENDPOINT};
use enclaveos_encrypted_fs::error::*;
use enclaveos_encrypted_fs::utils::find_env_or_err;
use enclaveos_encrypted_fs::EncryptedVolume;
use rand::distributions::Alphanumeric;
use rand::{Rng, RngCore};
use tokio::fs;

const TEST_RW_DEVICE: &str = "rw_device";
const TEST_MOUNT_POINT: &str = "rw_mount";
const RW_DEVICE_SIZE: u64 = 1 * 1024 * 1024 * 1024;
const SECURITY_OBJECT_PREFIX: &str = "fortanix-overlayfs-security-object-build-";
const DERIVATION_DATA_IV: &str = "any-16-char-seqs";

/// This is a sample program to help demonstrate how this crate can be used to setup an
/// encrypted filesystem and use DSM to protect the device passphrase.
#[tokio::main]
async fn main() -> Result<()> {
    // Obtain credentials to access DSM
    let dsm_api_key = find_env_or_err("DSM_API_KEY").map_err(|e| Error::GenericError(e))?;
    let dsm_url = find_env_or_err("DSM_ENDPOINT").unwrap_or(DEFAULT_DSM_ENDPOINT.to_string());
    let conn_info = ClientConnectionInfo {
        fs_api_key: Some(dsm_api_key.clone()),
        auth_cert: None,
        dsm_url: dsm_url.clone(),
    };

    let dsm_ops_handler = DsmFsOps::new(conn_info, SECURITY_OBJECT_PREFIX.into(), DERIVATION_DATA_IV.into())
        .map_err(|e| Error::GenericError(e.to_string()))?;

    // Create a test blockfile of size 1GB
    let mut file = fs::File::create(TEST_RW_DEVICE)
        .await
        .map_err(|e| Error::GenericError(e.to_string()))?;
    file.set_len(RW_DEVICE_SIZE)
        .await
        .map_err(|e| Error::GenericError(e.to_string()))?;

    // Create the mount point
    fs::create_dir(TEST_MOUNT_POINT)
        .await
        .map_err(|e| Error::GenericError(e.to_string()))?;

    // Setup encrypted filesystem
    let encryped_fs = EncryptedVolume::setup_encrypted_volume(Some(dsm_ops_handler), TEST_RW_DEVICE, TEST_MOUNT_POINT)
        .await
        .map_err(|e| Error::GenericError(e))?;

    // Write some data to the encrypted filesystem
    let rand_filename: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    let testfile = Path::new(TEST_MOUNT_POINT).join(&rand_filename);
    let mut testdata = vec![0u8; 1024];
    rand::thread_rng().fill_bytes(&mut testdata);

    fs::write(&testfile, &testdata)
        .await
        .map_err(|e| Error::GenericError(e.to_string()))?;

    // Unmount the encrypted filesystem
    encryped_fs
        .cleanup_encrypted_volume()
        .await
        .map_err(|e| Error::GenericError(e))?;

    // Test that the sample file created doesn't exist now, since the filesystem is unmounted
    assert!(!Path::exists(&testfile));

    // Open and re-mount up the filesystem again
    let conn_info = ClientConnectionInfo {
        fs_api_key: Some(dsm_api_key),
        auth_cert: None,
        dsm_url,
    };

    let dsm_ops_handler = DsmFsOps::new(conn_info, SECURITY_OBJECT_PREFIX.into(), DERIVATION_DATA_IV.into())
        .map_err(|e| Error::GenericError(e.to_string()))?;

    let efs = EncryptedVolume::setup_encrypted_volume(Some(dsm_ops_handler), TEST_RW_DEVICE, TEST_MOUNT_POINT)
        .await
        .map_err(|e| Error::GenericError(e))?;

    // Ensure data that was previously written can be read again
    let contents = fs::read(testfile).await.map_err(|e| Error::GenericError(e.to_string()))?;

    assert_eq!(&contents, &testdata);

    // Cleanup
    efs.cleanup_encrypted_volume().await.map_err(|e| Error::GenericError(e))?;
    fs::remove_dir_all(TEST_MOUNT_POINT)
        .await
        .map_err(|e| Error::GenericError(e.to_string()))?;
    fs::remove_file(TEST_RW_DEVICE)
        .await
        .map_err(|e| Error::GenericError(e.to_string()))?;

    // Exit
    Ok(())
}
