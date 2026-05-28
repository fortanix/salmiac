use clap::Parser;

/// This is a crate that has a WIP/debug implementation, with placeholder structures,
/// of the `setup_enclave_certification` function from
/// `vsock-proxy/enclave/src/enclave.rs`.
/// This is created due to not wanting a circular dependency between the crates.
/// The most important function and members are replicated, but should not be used anywhere else.
/// The goal is to test things like reading the files the embedded attestation client produces
/// and converting them into a format that the rest of the code expects.
mod debug {
    use mbedtls::pk::Pk;
    use std::ffi::CString;
    use std::fs;
    use std::path::{Path, PathBuf};

    #[derive(Debug, Clone, PartialEq)]
    pub(super) struct CertificateConfig {
        pub alt_names: Vec<String>,
    }

    pub(super) struct CertificateResult {
        pub certificate: String,
        #[allow(unused)]
        pub key: Pk,
    }

    impl std::fmt::Debug for CertificateResult {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("CertificateResult")
                .field("certificate", &self.certificate)
                .field("key", &"Not Displayable")
                .finish()
        }
    }

    #[derive(Debug)]
    pub(super) struct CertificateWithPath {
        #[allow(unused)]
        pub(crate) certificate_result: CertificateResult,
        #[allow(unused)]
        key_path: PathBuf,
        #[allow(unused)]
        certificate_path: PathBuf,
    }

    impl CertificateWithPath {
        pub(crate) fn new(
            certificate_result: CertificateResult,
            _cert_config: &CertificateConfig,
            _fs_root: &Path,
        ) -> Self {
            let key_path = PathBuf::from("/test/key");
            let certificate_path = PathBuf::from("/test/cert");

            CertificateWithPath {
                certificate_result,
                key_path,
                certificate_path,
            }
        }
    }

    pub(super) fn setup_enclave_certification_embedded_client(
        app_config_id: &Option<String>,
        cert_config: &CertificateConfig,
        fs_root: &Path,
    ) -> Result<CertificateWithPath, String> {
        // For SNP, for the time being, an embedded attestation agent is used to create certificates.
        // VSOCK is hardcoded inside the client; the client will directly reach out to the node agent
        use embedded_attestation_client::EmbeddedSnpAttestationClient;

        let mut client = EmbeddedSnpAttestationClient::new()?;
        // We will write out the key and certificate to the temporary working directory of the embedded
        // client, and read them into memory
        let temp_dir = client.temp_dir_path();
        let cert_path = temp_dir.join("cert");
        let key_path = temp_dir.join("key");
        client
            .app_cert_key_file_name(&key_path)
            .app_cert_file_name(&cert_path)
            .app_config_id(app_config_id.clone())
            .work_dir(Some(temp_dir));
        if !cert_config.alt_names.is_empty() {
            client.app_cert_alt_names(Some(cert_config.alt_names.clone()));
        }
        client.run()?;

        // Check if the key and cert have been created
        if !&cert_path.exists() {
            return Err(format!(
                "Expected embedded client cert does not exist: {}",
                cert_path.display()
            ));
        }
        if !&key_path.exists() {
            return Err(format!(
                "Expected embedded client key does not exist: {}",
                key_path.display()
            ));
        }

        // Read the key and cert and convert them into values that can be returned
        let cert_pem = fs::read_to_string(cert_path)
            .map_err(|e| format!("Failed to read embedded client cert file: {}", e))?;
        let key_pem = fs::read_to_string(key_path)
            .map_err(|e| format!("Failed to read  embedded client key file: {}", e))?;
        let key_pem_cstr = CString::new(key_pem.as_bytes()).map_err(|e| {
            format!(
                "Failed to convert embedded client key file bytes to CString: {}",
                e
            )
        })?;

        let key_pk = Pk::from_private_key(key_pem_cstr.as_bytes_with_nul(), None).map_err(|e| {
            format!(
                "Failed to convert embedded client key file to mbedtls PK: {}",
                e
            )
        })?;

        Ok(CertificateWithPath::new(
            CertificateResult {
                certificate: cert_pem,
                key: key_pk,
            },
            cert_config,
            fs_root,
        ))
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Flag to run only the basic embedded client, without the other processing
    #[clap(long, short, action)]
    basic: bool,
}

fn main() {
    env_logger::init();

    let args = Args::parse();

    // Only run the embedded client, without the vsock-proxy enclave flow
    if args.basic {
        use embedded_attestation_client::EmbeddedSnpAttestationClient;
        let client = EmbeddedSnpAttestationClient::new()
            .expect("Could not set up embedded SNP attestation client");
        client.run().expect("Attestation client execution failed");
        return;
    }

    let result = debug::setup_enclave_certification_embedded_client(
        &None,
        &debug::CertificateConfig { alt_names: vec![] },
        &std::env::current_dir().unwrap(),
    );

    println!("{:?}", result)
}
