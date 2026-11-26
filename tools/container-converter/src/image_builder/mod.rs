/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::Path;

use crate::{ConverterError, ConverterErrorKind};

#[cfg(any(platform = "snp", platform = "tdx", platform = "simulator"))]
pub(crate) mod blob_finder;
pub(crate) mod enclave;
pub(crate) mod parent;

const INSTALLATION_DIR: &'static str = "/opt/fortanix/enclave-os";
const ORIG_ENV_LIST_PATH: &'static str = "original-parent.env";

const MEGA_BYTE: u64 = 1024 * 1024;
const fn bytes_to_mb_ceil(bytes: u64) -> u64 {
    bytes.div_ceil(MEGA_BYTE) * MEGA_BYTE
}

fn rust_log_env_var_kv(project_name: &str) -> (String, String) {
    let log_level = if cfg!(debug_assertions) {
        "debug"
    } else {
        "info"
    };

    (
        "RUST_LOG".to_string(),
        format!("{}={}", project_name, log_level),
    )
}

fn rust_log_env_var(project_name: &str) -> String {
    let (k, v) = rust_log_env_var_kv(project_name);
    format!("{k}={v}")
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
    use docker_image_reference::{Reference, Reference as DockerReference};
    use shiplift::container::ContainerCreateInfo;
    use shiplift::image::ImageDetails;
    use tar::{Builder, Header};
    use tempfile::TempDir;

    use crate::docker::DockerUtil;
    use crate::image::ImageWithDetails;
    use crate::image_builder::enclave::GenericEnclaveImageBuilder;

    struct TestDockerDaemon {}

    #[async_trait]
    impl DockerUtil for TestDockerDaemon {
        async fn get_latest_image_details(
            &self,
            _image: &DockerReference<'_>,
        ) -> Result<ImageDetails, String> {
            todo!()
        }

        async fn get_local_image_details(
            &self,
            _image: &Reference<'_>,
        ) -> Result<ImageDetails, String> {
            todo!()
        }

        async fn load_image(&self, _tar_path: &str) -> Result<String, String> {
            todo!()
        }

        async fn push_image(&self, _image: &ImageWithDetails) -> Result<(), String> {
            todo!()
        }

        async fn build_image_from_archive(
            &self,
            _archive: File,
            _image: &Reference<'_>,
        ) -> Result<(), String> {
            todo!()
        }

        async fn create_container(
            &self,
            image: &Reference<'_>,
        ) -> Result<ContainerCreateInfo, String> {
            Ok(ContainerCreateInfo {
                id: image.to_string(),
                warnings: None,
            })
        }

        async fn force_delete_container(&self, _container_name: &str) -> Result<(), String> {
            Ok(())
        }

        async fn export_container_file_system(
            &self,
            _container_name: &str,
            file: &mut File,
        ) -> Result<(), String> {
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

        let client_image_reference =
            DockerReference::from_str("test").expect("Failed creating docker reference");
        let enclave_base_image =
            &DockerReference::from_str("test").expect("Failed creating docker reference");
        let enclave_builder = GenericEnclaveImageBuilder {
            client_image_reference: &client_image_reference,
            dir: &temp_dir,
            enclave_base_image,
        };

        let mut archive = enclave_builder
            .export_image_file_system(&TestDockerDaemon {}, &temp_dir.path().join("fs.tar"))
            .await
            .expect("Failed exporting image file system");

        archive
            .unpack(temp_dir.path())
            .expect("Failed unpacking archive.");

        let mut result_file = fs::OpenOptions::new()
            .read(true)
            .open(&temp_dir.path().join(TEST_FS_FILE))
            .expect("Cannot open result file");

        let mut result = String::new();
        result_file
            .read_to_string(&mut result)
            .expect("Failed reading result file");

        assert_eq!(result, TEST_DATA)
    }
}
