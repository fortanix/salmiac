//! This crate builds the SNP Attestation Client and embeds it inside the library.
//! This allows it to be unpacked and run from a temporary directory

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// This name is set in `build.rs` file, so that it does not have to be changed in more than one
/// location in the event of a name change.
static ATTESTATION_CLIENT_BIN_NAME: &str = env!("ATTESTATION_CLIENT_BIN_NAME");

/// The executable copied from Roche repo's build output, as triggered by `build.rs`
static ATTESTATION_CLIENT_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/",
    env!("ATTESTATION_CLIENT_BIN_NAME")
));

/// Helper struct for the embedded SNP Attestation client.
pub struct EmbeddedSnpAttestationClient {
    // TODO: Consider using tempfile::SpooledTempFile to keep everything in memory
    /// Directory where the SNP Attestation Client will be unpacked to
    temp_dir: TempDir,
}

impl EmbeddedSnpAttestationClient {
    fn attest_client_path(&self) -> PathBuf {
        self.temp_dir.path().join(ATTESTATION_CLIENT_BIN_NAME)
    }

    /// Create a new instance of the embedded attestation client.
    /// This creates a temporary directory that holds the binary,
    /// and changes file permissions to allow execution.
    /// The binary is removed along with the temporary directory after this
    /// structure exits scope.
    pub fn new() -> Result<Self, String> {
        // Create structure with temp dir to hold the binary
        let client = EmbeddedSnpAttestationClient {
            temp_dir: TempDir::new().map_err(|e| e.to_string())?,
        };
        // Copy the binary to the directory
        let client_file_path = client.attest_client_path();
        let mut client_file = File::create(&client_file_path).map_err(|e| e.to_string())?;
        client_file
            .write_all(ATTESTATION_CLIENT_BYTES)
            .map_err(|e| e.to_string())?;
        client_file.flush().map_err(|e| e.to_string())?;
        // Make the file executable
        let chmod_status = Command::new("chmod")
            .args(["u+x", &client_file_path.to_str().unwrap()])
            .status()
            .map_err(|e| e.to_string())?;
        if !chmod_status.success() {
            return Err(format!(
                "Chmod returned error status: {}",
                chmod_status.code().unwrap_or(1)
            ));
        }

        Ok(client)
    }

    /// Executes the Attestation Client. This will run a child process.
    /// If successful, this will create the local and remote attestation certificates.
    pub fn run(&self) -> Result<(), String> {
        Command::new(self.attest_client_path())
            .status()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
