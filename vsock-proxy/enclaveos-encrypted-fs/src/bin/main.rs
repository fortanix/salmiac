use tokio::fs;
use enclaveos_encrypted_fs::dsm_key_config::ClientConnectionInfo;
use enclaveos_encrypted_fs::utils::find_env_or_err;
use enclaveos_encrypted_fs::error::*;

#[tokio::main]
async fn main() -> Result<()> {
    // Create a blockfile of size 1GB
    let device_path = "rw_device";
    let zero_buf = vec![0u8; 1 * 1024 * 1024 * 1024];
    fs::write(device_path, zero_buf).await.map_err(|e| Error::GenericError(e.to_string()))?;

    let mount_path = "rw_mount";
    fs::create_dir(mount_path).await.map_err(|e| Error::GenericError(e.to_string()))?;

    let dsm_api_key = find_env_or_err("DSM_API_KEY").map_err(|e| Error::GenericError(e))?;
    let dsm_url = find_env_or_err("DSM_ENDPOINT").unwrap_or("https://amer.smartkey.io/".to_string());
    let conn_info = ClientConnectionInfo {
        fs_api_key: Some(dsm_api_key),
        auth_cert: None,
        dsm_url
    };

    // Call mount_fs
    enclaveos_encrypted_fs::mount_read_write_file_system(Some(conn_info), device_path, mount_path).await.map_err(|e| Error::GenericError(e))?;

    // Write data
    fs::write("rw_mount/test.txt", "hello world").await.map_err(|e| Error::GenericError(e.to_string()))?;

    // Call umount

    // Mount again

    // Ensure data written can be read again

    // Exit
    Ok(())
}
