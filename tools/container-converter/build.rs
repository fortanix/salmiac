use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::result::Result;
use std::{env, fs};

use salmiac_build_support::{Platform, DEFAULT_PLATFORM};

// Enclave startup is statically linked to musl instead of glibc
// to avoid problems runtime linking errors with libnss
const ENCLAVE_STARTUP_TARGET: &str = "x86_64-unknown-linux-musl";

const SALMIAC_PLATFORM_ENV: &str = "SALMIAC_PLATFORM";

const VSOCK_PROXY_BIN_DIR: &str = "../../vsock-proxy/target";

const ENCLAVE_STARTUP_BIN_DIR: &str = "../../enclave-startup/target";

const RESOURCES_PARENT_DIR: &str = "src/resources/parent";

const RESOURCES_ENCLAVE_DIR: &str = "src/resources/enclave";

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo::rerun-if-env-changed=EMBED_ATTEST_CLIENT_ROCHE_NAME");
    println!("cargo::rerun-if-env-changed=EMBED_ATTEST_CLIENT_ROCHE_PATH");

    for dir in &[
        PathBuf::from("../../vsock-proxy"),
        PathBuf::from("../../enclave-startup"),
        PathBuf::from("../../embedded-attestation-client"),
    ] {
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_entry(|e| {
                // Skip target dirs
                if e.file_type().is_dir() {
                    !e.file_name().to_string_lossy().starts_with("target")
                } else {
                    true
                }
            })
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                println!("cargo::rerun-if-changed={}", entry.path().display());
            }
        }
    }

    let platform = Platform::emit_cfg_from_env_or(*DEFAULT_PLATFORM);

    let (bin_dir, cargo_build_flag) = if cfg!(debug_assertions) {
        (Path::new("debug"), None)
    } else {
        (Path::new("release"), Some("--release"))
    };

    let vsock_proxy_bin_dir = Path::new(VSOCK_PROXY_BIN_DIR).join(bin_dir);
    let enclave_startup_bin_dir = Path::new(ENCLAVE_STARTUP_BIN_DIR)
        .join(ENCLAVE_STARTUP_TARGET)
        .join(bin_dir);
    let resources_parent_dir = Path::new(RESOURCES_PARENT_DIR);
    let resources_enclave_dir = Path::new(RESOURCES_ENCLAVE_DIR);

    fs::create_dir_all(resources_enclave_dir).expect(&format!(
        "Failed creating {} dir",
        resources_enclave_dir.display()
    ));

    fs::create_dir_all(resources_parent_dir).expect(&format!(
        "Failed creating {} dir",
        resources_parent_dir.display()
    ));

    let current_dir = env::current_dir().expect("Failed retrieving current directory");

    build_print::info!("Building vsock-proxy");
    let status = {
        let mut result = Command::new("cargo");

        result
            .current_dir(current_dir.join("../../vsock-proxy"))
            .env(SALMIAC_PLATFORM_ENV, platform.as_ref())
            .arg("build");

        if let Some(build_flag) = cargo_build_flag {
            result.arg(build_flag);
        }

        result
    }
    .status()
    .expect("Failed to build vsock-proxy project");
    build_print::info!("Done building vsock-proxy");

    assert!(
        status.success(),
        "failed to build vsock-proxy project: {}",
        status
    );

    fs::copy(
        vsock_proxy_bin_dir.join("enclave"),
        resources_enclave_dir.join("enclave"),
    )
    .expect("Failed to copy enclave bin");
    fs::copy(
        vsock_proxy_bin_dir.join("parent"),
        resources_parent_dir.join("parent"),
    )
    .expect("Failed to copy parent bin");

    build_print::info!("Building enclave-startup");
    let status = {
        let mut result = Command::new("cargo");

        result
            .current_dir(current_dir.join("../../enclave-startup"))
            .arg("build");

        if let Some(build_flag) = cargo_build_flag {
            result.arg(build_flag);
        }

        result.arg("--target").arg(ENCLAVE_STARTUP_TARGET);

        result
    }
    .status()
    .expect("Failed to build enclave-startup project");

    assert!(
        status.success(),
        "failed to build enclave-startup project: {}",
        status
    );
    build_print::info!("Done building enclave-startup");

    fs::copy(
        enclave_startup_bin_dir.join("enclave-startup"),
        resources_enclave_dir.join("enclave-startup"),
    )
    .expect("Failed to copy enclave-startup bin");

    Ok(())
}
