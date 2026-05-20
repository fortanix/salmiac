//! This crate builds the SNP Attestation Client and embeds it inside the library.
//! This allows it to be unpacked and run from a temporary directory

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
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

static APP_CERT_ALT_NAMES_VAR_NAME: &'static str = "APP_CERT_ALT_NAMES";
static APPCONFIG_ID_VAR_NAME: &'static str = "APPCONFIG_ID";
static APP_CERT_KEY_FILE_NAME_VAR_NAME: &'static str = "APP_CERT_KEY_FILE_NAME";
static APP_CERT_FILE_NAME_VAR_NAME: &'static str = "APP_CERT_FILE_NAME";

pub static APP_CERT_KEY_FILE_NAME: &'static str = "/opt/fortanix/attestation-client/key.pem";
pub static APP_CERT_FILE_NAME: &'static str = "/opt/fortanix/attestation-client/cert.pem";

/// Helper struct for the embedded SNP Attestation client.
pub struct EmbeddedSnpAttestationClient {
    // TODO: Consider using tempfile::SpooledTempFile to keep everything in memory
    /// Directory where the SNP Attestation Client will be unpacked to
    temp_dir: TempDir,
    app_cert_key_file_name: PathBuf,
    app_cert_file_name: PathBuf,
    app_cert_alt_names: Option<Vec<String>>,
    appconfig_id: Option<String>,
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
            app_cert_key_file_name: PathBuf::from(APP_CERT_KEY_FILE_NAME),
            app_cert_file_name: PathBuf::from(APP_CERT_FILE_NAME),
            app_cert_alt_names: None,
            appconfig_id: None,
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

    pub fn app_cert_key_file_name(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.app_cert_key_file_name = path.as_ref().to_path_buf();
        self
    }

    pub fn app_cert_file_name(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.app_cert_file_name = path.as_ref().to_path_buf();
        self
    }

    pub fn app_cert_alt_names(&mut self, names: Option<Vec<String>>) -> &mut Self {
        self.app_cert_alt_names = names;
        self
    }

    pub fn app_config_id(&mut self, config_id: Option<String>) -> &mut Self {
        self.appconfig_id = config_id;
        self
    }

    /// Executes the Attestation Client. This will run a child process.
    /// If successful, this will create the local and remote attestation certificates.
    pub fn run(&self) -> Result<(), String> {
        let mut cmd = Command::new(self.attest_client_path());
        // Clear any existing environmental variables to prevent pollution, only values from
        // the object should be used
        for var in [
            APP_CERT_ALT_NAMES_VAR_NAME,
            APPCONFIG_ID_VAR_NAME,
            APP_CERT_KEY_FILE_NAME_VAR_NAME,
            APP_CERT_FILE_NAME_VAR_NAME,
        ] {
            cmd.env_remove(var);
        }
        // Set the key and cert output directories
        cmd.envs([
            (
                APP_CERT_KEY_FILE_NAME_VAR_NAME,
                &self.app_cert_key_file_name,
            ),
            (APP_CERT_FILE_NAME_VAR_NAME, &self.app_cert_file_name),
        ]);
        // Set the cert alt names, if configured
        if let Some(alt_names) = &self.app_cert_alt_names {
            cmd.env(APP_CERT_ALT_NAMES_VAR_NAME, alt_names.join(","));
        }
        // Set the app config id, if configured
        if let Some(config_id) = &self.appconfig_id {
            cmd.env(APPCONFIG_ID_VAR_NAME, config_id);
        }

        cmd.status().map_err(|e| e.to_string())?;
        Ok(())
    }
}
