use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::result::Result;

use salmiac_build_support::{Platform, DEFAULT_PLATFORM};

const SALMIAC_PLATFORM_ENV: &str = "SALMIAC_PLATFORM";
const RESOURCES_PARENT_DIR: &str = "src/resources/parent";
const RESOURCES_ENCLAVE_DIR: &str = "src/resources/enclave";

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("CARGO_MANIFEST_DIR is not set")?);
    let repo_root = manifest_dir.join("../..").canonicalize()?;
    let scripts_dir = repo_root.join("scripts");
    let vsock_proxy_build_script = scripts_dir.join("build-vsock-proxy-musl.sh");
    let enclave_startup_build_script = scripts_dir.join("build-enclave-startup-musl.sh");
    for path in [
        &vsock_proxy_build_script,
        &enclave_startup_build_script,
        &repo_root.join("vsock-proxy"),
        &repo_root.join("enclave-startup"),
    ] {
        for entry in walkdir::WalkDir::new(path)
            .into_iter()
            .filter_entry(|e| {
                // Skip target dirs.
                !e.file_type().is_dir() || !e.file_name().to_string_lossy().starts_with("target")
            })
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                println!("cargo::rerun-if-changed={}", entry.path().display());
            }
        }
    }

    let platform = Platform::emit_cfg_from_env_or(*DEFAULT_PLATFORM);
    let build_type = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let resources_parent_dir = manifest_dir.join(RESOURCES_PARENT_DIR);
    let resources_enclave_dir = manifest_dir.join(RESOURCES_ENCLAVE_DIR);

    build_vsock_proxy(
        &vsock_proxy_build_script,
        build_type,
        platform,
        &resources_enclave_dir.join("enclave"),
        &resources_parent_dir.join("parent"),
    )?;
    build_enclave_startup(
        &enclave_startup_build_script,
        build_type,
        &resources_enclave_dir.join("enclave-startup"),
    )?;

    Ok(())
}

fn build_vsock_proxy(
    build_script: &Path,
    build_type: &str,
    platform: Platform,
    enclave_out_path: &Path,
    parent_out_path: &Path,
) -> Result<(), Box<dyn Error>> {
    build_print::info!("Building vsock-proxy");
    let mut cmd = Command::new(build_script);
    cmd.env(SALMIAC_PLATFORM_ENV, platform.as_ref())
        // The converter's Cargo process holds its target-directory lock.
        // Let the helper use its project's target directory instead.
        .env_remove("CARGO_TARGET_DIR")
        .arg("--build-type")
        .arg(build_type)
        .arg("--enclave-out-path")
        .arg(enclave_out_path)
        .arg("--parent-out-path")
        .arg(parent_out_path);
    run_build_script(cmd)?;
    build_print::info!("Done building vsock-proxy");
    Ok(())
}

fn build_enclave_startup(
    build_script: &Path,
    build_type: &str,
    out_path: &Path,
) -> Result<(), Box<dyn Error>> {
    build_print::info!("Building enclave-startup");
    let mut cmd = Command::new(build_script);
    cmd.env_remove("CARGO_TARGET_DIR")
        .arg("--build-type")
        .arg(build_type)
        .arg("--out-path")
        .arg(out_path);
    run_build_script(cmd)?;
    build_print::info!("Done building enclave-startup");
    Ok(())
}

fn run_build_script(mut command: Command) -> Result<(), Box<dyn Error>> {
    let output = command.output().map_err(|err| {
        format!(
            "Failed to execute {:?} build script: {}",
            command.get_program(),
            err
        )
    })?;
    if !output.status.success() {
        eprintln!(
            "{:?} build script failed: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            command.get_program(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        return Err(format!(
            "Failed to build {:?} project: {}",
            command.get_program(),
            output.status
        )
        .into());
    }
    Ok(())
}
