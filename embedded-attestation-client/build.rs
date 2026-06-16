use build_support::Platform;
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

// Defines attestation_client_bin_name macro
// This allows for the name to be changed in only one place
include!("src/build_shared.rs");

fn main() {
    if let Err(err) = Platform::emit_cfg_from_env() {
        panic!(
            "This executable must be built with the correct configuration: {}",
            err
        );
    }

    println!(
        "cargo::warning=The embedded-attestation-client will only rebuild if the \
     attestation-client source files are changed, other changes require a manual rebuild"
    );

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir_path = PathBuf::from(&out_dir);

    // Run a build and copy the attestation client binary to include into the system
    let build_script_dir = std::env::current_dir().unwrap();
    // `roche/salmiac/salmiac-runner/embedded-attestation-client` is the usual location for this manifest
    let repos_dir = build_script_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    // EMBEDDED_ATTEST_CLIENT_ROCHE_NAME allows a developer to use a Roche directory name besides "roche"
    let roche_repo_name = env::var("EMBED_ATTEST_CLIENT_ROCHE_NAME").unwrap_or("roche".to_string());
    // As an alternative, if Salmiac is out of tree from Roche (standalone),
    // the Roche location can be indicated using EMBED_ATTEST_CLIENT_ROCHE_PATH
    let roche_dir = if let Ok(roche_path) = env::var("EMBED_ATTEST_CLIENT_ROCHE_PATH") {
        PathBuf::from(roche_path)
    } else {
        repos_dir.join(roche_repo_name)
    };
    build_print::info!(
        "Roche directory for attestation client build: {}",
        roche_dir.display()
    );
    if !roche_dir
        .try_exists()
        .expect("Roche directory does not exist")
    {
        panic!("Roche directory does not exist");
    }
    let attest_client_dir = roche_dir.join("product-packages/services/malbork/attestation-client");

    for env_var in [
        "EMBED_ATTEST_CLIENT_ROCHE_NAME",
        "EMBED_ATTEST_CLIENT_ROCHE_PATH",
        "EMBED_ATTEST_CLIENT_ROCHE_TOOLCHAIN",
    ] {
        println!("cargo::rerun-if-env-changed={}", env_var);
    }

    // Rebuild if this file has changed
    println!("cargo::rerun-if-changed=build.rs");

    // Re-run the build if any of the source files in the Attestation Client project have changed
    for entry in walkdir::WalkDir::new(&attest_client_dir)
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

    let target_profile = env::var("PROFILE").unwrap();
    let target_dir = roche_dir.join("target").join(&target_profile);

    // The toolchain can be provided by either an environmental variable, EMBED_ATTEST_CLIENT_ROCHE_TOOLCHAIN,
    // or by the toolchain file in Roche; the latter is preferable
    let toolchain = if let Ok(env_roche_toolchain) = env::var("EMBED_ATTEST_CLIENT_ROCHE_TOOLCHAIN")
    {
        env_roche_toolchain
    } else {
        // Get the toolchain version used in Roche, as we cannot use the Salmiac toolchain
        let mut buf = String::new();
        File::open(roche_dir.join("rust-toolchain.toml"))
            .expect("Could not find rust-toolchain.toml file")
            .read_to_string(&mut buf)
            .expect("Failed to read rust-toolchain.toml file");
        let table =
            toml::from_str::<toml::Value>(&buf).expect("Could not parse rust-toolchain.toml");
        let toml_roche_toolchain = if let toml::Value::Table(table) = table {
            if let toml::Value::Table(toolchain_table) = table.get("toolchain").unwrap() {
                toolchain_table["channel"]
                    .as_str()
                    .expect("Could not find channel")
                    .to_string()
            } else {
                panic!("Could not \"toolchain\" table in rust-toolchain.toml");
            }
        } else {
            panic!("Could not get roche toolchain channel");
        };
        toml_roche_toolchain
    };

    // We build the real agent for SNP, otherwise make a dummy
    let platform = Platform::from_env().unwrap();
    match platform {
        Platform::Snp | Platform::Tdx => {
            // Run the attestation client build
            let mut cmd = Command::new("cargo");
            cmd.args(["build"])
                .current_dir(attest_client_dir)
                .env_remove("RUSTC")
                .env("RUSTUP_TOOLCHAIN", toolchain);
            // Debug profile should not be supplied as a profile flag, other ones can be
            if target_profile != "debug" {
                cmd.arg(format!("--profile={}", &target_profile));
            }
            let build_status = cmd.status().unwrap();
            if !build_status.success() {
                panic!("Parent Roche repo Attestation Client build failed");
            }

            // Copy the attestation client to the output directory
            let attestation_client_bin = match platform {
                Platform::Snp => attestation_client_sevsnp_bin_name!(),
                Platform::Tdx => attestation_client_tdx_bin_name!(),
                _ => panic!("Unreachable platform pattern matching")
            };

            std::fs::copy(
                target_dir.join(attestation_client_bin),
                out_dir_path.clone().join(attestation_client_target_bin_name!()),
            )
            .expect("Could not copy attestation client binary");

            build_print::info!(
                "Attestation client copied to: {}",
                out_dir_path.display()
            );
        }
        _ => {
            println!(
                "cargo::warning=The embedded-attestation-client is being built with a dummy executable for \
        a non-SNP platform, it will be non-functional"
            );
            println!("cargo::rerun-if-changed=src/bin/dummy.c");
            let mut cmd = Command::new("gcc");
            let src_file = build_script_dir.clone().join("src/bin/dummy.c");
            cmd.args([src_file.display().to_string().as_str(), "-o", "dummy"])
                .current_dir(&out_dir_path);
            let build_status = cmd.status().unwrap();
            if !build_status.success() {
                panic!("Dummy Attestation Client build failed");
            }

            // Copy the dummy file to the output directory with the expected name
            std::fs::copy(
                out_dir_path.clone().join("dummy"),
                out_dir_path.clone().join(attestation_client_target_bin_name!()),
            )
            .expect("Could not copy attestation client binary");
        }
    }
}
