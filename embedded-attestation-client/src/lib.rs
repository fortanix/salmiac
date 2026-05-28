#![allow(unexpected_cfgs)]
//! This crate builds the SNP Attestation Client and embeds it inside the library.
//! This allows it to be unpacked and run from a temporary directory

mod build_shared;
use build_shared::attestation_client_bin_name;

use log::{debug, Level};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// The executable copied from Roche repo's build output, as triggered by `build.rs`
static ATTESTATION_CLIENT_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/",
    attestation_client_bin_name!()
));

static APP_CERT_ALT_NAMES_VAR_NAME: &'static str = "APP_CERT_ALT_NAMES";
static APPCONFIG_ID_VAR_NAME: &'static str = "APPCONFIG_ID";
static APP_CERT_KEY_FILE_NAME_VAR_NAME: &'static str = "APP_CERT_KEY_FILE_NAME";
static APP_CERT_FILE_NAME_VAR_NAME: &'static str = "APP_CERT_FILE_NAME";

pub static APP_CERT_KEY_FILE_NAME: &'static str = "/opt/fortanix/attestation-client/key.pem";
pub static APP_CERT_FILE_NAME: &'static str = "/opt/fortanix/attestation-client/cert.pem";

/// Helper struct for the embedded SNP Attestation client.
#[derive(Debug)]
pub struct EmbeddedSnpAttestationClient {
    // TODO: Consider using tempfile::SpooledTempFile to keep everything in memory
    /// Directory where the SNP Attestation Client will be unpacked to
    temp_dir: TempDir,
    app_cert_key_file_name: PathBuf,
    app_cert_file_name: PathBuf,
    app_cert_alt_names: Option<Vec<String>>,
    appconfig_id: Option<String>,
    work_dir: Option<PathBuf>,
    log_level: Option<Level>,
}

impl EmbeddedSnpAttestationClient {
    fn attest_client_path(&self) -> PathBuf {
        self.temp_dir.path().join(attestation_client_bin_name!())
    }

    fn create_client_file(&self) -> std::io::Result<()> {
        let path = self.attest_client_path();

        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(true);

        // 0o755 = rwxr-xr-x (Standard readable/executable file)
        options.mode(0o755);

        let mut file = options.open(path)?;
        file.write_all(ATTESTATION_CLIENT_BYTES)?;
        file.flush()?;

        Ok(())
    }

    fn create_app_cert_dir() -> std::io::Result<()> {
        let app_cert_key = Path::new(APP_CERT_KEY_FILE_NAME);
        if let Some(parent) = app_cert_key.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let app_cert_file_name = Path::new(APP_CERT_FILE_NAME);
        if let Some(parent) = app_cert_file_name.parent() {
            std::fs::create_dir_all(parent)?;
        }

        Ok(())
    }

    pub fn temp_dir_path(&self) -> PathBuf {
        self.temp_dir.path().to_path_buf()
    }

    /// Create a new instance of the embedded attestation client.
    /// This creates a temporary directory that holds the binary,
    /// and changes file permissions to allow execution.
    /// The binary is removed along with the temporary directory after this
    /// structure exits scope.
    pub fn new() -> Result<Self, String> {
        // Create structure with temp dir to hold the binary
        debug!("Creating embedded attestation client object");
        debug!("Creating temporary directory for client");
        let client = EmbeddedSnpAttestationClient {
            temp_dir: TempDir::new().map_err(|e| e.to_string())?,
            app_cert_key_file_name: PathBuf::from(APP_CERT_KEY_FILE_NAME),
            app_cert_file_name: PathBuf::from(APP_CERT_FILE_NAME),
            app_cert_alt_names: None,
            appconfig_id: None,
            work_dir: None,
            log_level: None,
        };

        debug!("Creating file for client binary");
        client.create_client_file().map_err(|err| err.to_string())?;

        debug!("Creating app certificates directory");
        Self::create_app_cert_dir().map_err(|err| err.to_string())?;

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

    pub fn work_dir(&mut self, work_dir: Option<PathBuf>) -> &mut Self {
        self.work_dir = work_dir;
        self
    }

    pub fn log_level(&mut self, log_level: Option<Level>) -> &mut Self {
        self.log_level = log_level;
        self
    }

    /// Executes the Attestation Client. This will run a child process.
    /// If successful, this will create the local and remote attestation certificates.
    pub fn run(&self) -> Result<(), String> {
        debug!("Running embedded attestation client with Cert");
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
        // Set the work directory
        if let Some(work_dir) = &self.work_dir {
            cmd.current_dir(work_dir);
        }

        if let Some(level) = self.log_level {
            cmd.env("RUST_LOG", level.as_str());
        }

        debug!("Attestation client environment: {:?}", cmd.get_envs());

        let status = cmd.status().map_err(|e| e.to_string())?;
        if !status.success() {
            return Err(format!(
                "Embedded attestation client failed with status: {}",
                status
            ));
        }
        Ok(())
    }
}
