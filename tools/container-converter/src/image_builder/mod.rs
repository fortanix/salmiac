/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::{ConverterError, ConverterErrorKind};
use std::path::Path;

pub mod enclave;
pub mod parent;

const INSTALLATION_DIR: &'static str = "/opt/fortanix/enclave-os";
const ORIG_ENV_LIST_PATH: &'static str = "original-parent.env";

const MEGA_BYTE: u64 = 1024 * 1024;

fn rust_log_env_var(project_name: &str) -> String {
    let log_level = if cfg!(debug_assertions) { "debug" } else { "info" };

    format!("RUST_LOG={}={}", project_name, log_level)
}

/// Interprets <code>&[Path]</code> as a <code>&[str]</code>
fn path_as_str(arg: &Path) -> Result<&str, ConverterError> {
    arg.as_os_str().to_str().ok_or(ConverterError {
        message: format!("Cannot convert path {} to string.", arg.display()).to_string(),
        kind: ConverterErrorKind::InternalError,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Read;
    
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use docker_image_reference::{Reference, Reference as DockerReference};
    use shiplift::container::ContainerCreateInfo;
    use shiplift::image::{ContainerConfig, ImageDetails};
    use tar::{Builder, Header};
    use tempfile::TempDir;

    use crate::docker::DockerUtil;
    use crate::image::ImageWithDetails;
    use crate::image_builder::enclave::{EnclaveImageBuilder, get_image_env};
    use api_model::converter::ConverterOptions;

    struct TestDockerDaemon {}

    #[async_trait]
    impl DockerUtil for TestDockerDaemon {
        async fn get_latest_image_details(&self, _image: &DockerReference<'_>) -> Result<ImageDetails, String> {
            todo!()
        }

        async fn get_local_image_details(&self, _image: &Reference<'_>) -> Result<ImageDetails, String> {
            todo!()
        }

        async fn load_image(&self, _tar_path: &str) -> Result<(), String> {
            todo!()
        }

        async fn push_image(&self, _image: &ImageWithDetails) -> Result<(), String> {
            todo!()
        }

        async fn build_image_from_archive(&self, _archive: File, _image: &Reference<'_>) -> Result<(), String> {
            todo!()
        }

        async fn create_container(&self, image: &Reference<'_>) -> Result<ContainerCreateInfo, String> {
            Ok(ContainerCreateInfo {
                id: image.to_string(),
                warnings: None,
            })
        }

        async fn force_delete_container(&self, _container_name: &str) -> Result<(), String> {
            Ok(())
        }

        async fn export_container_file_system(&self, _container_name: &str, file: &mut File) -> Result<(), String> {
            let mut header = Header::new_gnu();
            let data: &[u8] = TEST_DATA.as_bytes();

            header.set_size(data.len() as u64);
            header.set_cksum();

            let mut archive = Builder::new(file);
            archive
                .append_data(&mut header, TEST_FS_FILE, data)
                .expect("Failed writing test data to archive.");

            Ok(())
        }
    }

    const TEST_DATA: &'static str = "Hello World";

    const TEST_FS_FILE: &'static str = "test-fs";

    #[tokio::test]
    async fn export_image_file_system_correct_pass() {
        let temp_dir = TempDir::new().expect("Failed creating temp dir");

        let client_image_reference = DockerReference::from_str("test").expect("Failed creating docker reference");
        let enclave_base_image = &DockerReference::from_str("test").expect("Failed creating docker reference");
        let enclave_builder = EnclaveImageBuilder {
            client_image_reference: &client_image_reference,
            dir: &temp_dir,
            enclave_base_image,
        };

        let mut archive = enclave_builder
            .export_image_file_system(&TestDockerDaemon {}, &temp_dir.path().join("fs.tar"))
            .await
            .expect("Failed exporting image file system");

        archive.unpack(temp_dir.path()).expect("Failed unpacking archive.");

        let mut result_file = fs::OpenOptions::new()
            .read(true)
            .open(&temp_dir.path().join(TEST_FS_FILE))
            .expect("Cannot open result file");

        let mut result = String::new();
        result_file.read_to_string(&mut result).expect("Failed reading result file");

        assert_eq!(result, TEST_DATA)
    }

    #[test]
    fn enclave_settings_ctor_should_produce_correct_env_vars_string() {
        let reference = DockerReference::from_str("test").unwrap();
        let details = ImageDetails {
            architecture: "".to_string(),
            author: "".to_string(),
            comment: "".to_string(),
            config: ContainerConfig {
                attach_stderr: false,
                attach_stdin: false,
                attach_stdout: false,
                cmd: None,
                domainname: "".to_string(),
                entrypoint: None,
                env: None,
                exposed_ports: None,
                hostname: "".to_string(),
                image: "".to_string(),
                labels: None,
                on_build: None,
                open_stdin: false,
                stdin_once: false,
                tty: false,
                user: "".to_string(),
                working_dir: "".to_string(),
            },
            created: DateTime::<Utc>::MAX_UTC,
            docker_version: "".to_string(),
            id: "".to_string(),
            os: "".to_string(),
            parent: "".to_string(),
            repo_tags: None,
            repo_digests: None,
            size: 0,
            virtual_size: Some(0),
        };

        let mut input_image = ImageWithDetails { reference, details };

        let mut converter_options = ConverterOptions {
            allow_cmdline_args: None,
            allow_docker_pull_failure: None,
            app: None,
            ca_certificates: vec![],
            certificates: vec![],
            debug: None,
            entry_point: vec![],
            entry_point_args: vec![],
            push_converted_image: None,
            env_vars: vec![],
            java_mode: None,
            enable_overlay_filesystem_persistence: None,
            ccm_configuration: None,
            dsm_configuration: None,
        };

        let mut test = |input_image_env_vars: Option<Vec<String>>,
                        converter_request_env_vars: Vec<String>,
                        reference: Vec<String>|
         -> () {
            input_image.details.config.env = input_image_env_vars;
            converter_options.env_vars = converter_request_env_vars;

            let result = get_image_env(&input_image, &converter_options);

            assert_eq!(result, reference);
        };

        test(
            Some(vec![
                "A=A_VALUE".to_string(),
                "B=B_VALUE".to_string(),
                "C=C_VALUE".to_string(),
            ]),
            vec!["A=A_VALUE_NEW".to_string(), "C=C_VALUE_NEW".to_string()],
            vec![
                "A=A_VALUE".to_string(),
                "B=B_VALUE".to_string(),
                "C=C_VALUE".to_string(),
                "A=A_VALUE_NEW".to_string(),
                "C=C_VALUE_NEW".to_string(),
            ],
        );

        test(
            None,
            vec!["A=A_VALUE_NEW".to_string(), "C=C_VALUE_NEW".to_string()],
            vec!["A=A_VALUE_NEW".to_string(), "C=C_VALUE_NEW".to_string()],
        );

        test(
            Some(vec![
                "A=A_VALUE".to_string(),
                "B=B_VALUE".to_string(),
                "C=C_VALUE".to_string(),
            ]),
            vec![],
            vec!["A=A_VALUE".to_string(), "B=B_VALUE".to_string(), "C=C_VALUE".to_string()],
        );
    }
}
