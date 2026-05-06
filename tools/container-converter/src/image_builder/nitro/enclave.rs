/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::Path;
use std::sync::mpsc::Sender;

use api_model::enclave::{EnclaveManifest, UserConfig};
use docker_image_reference::Reference as DockerReference;
use serde::Deserialize;

use crate::docker::DockerUtil;
use crate::file::BuildContext;
use crate::image::{ImageKind, ImageToClean};
use crate::image_builder::enclave::EnclaveSettings;
use crate::{run_subprocess, ConverterError, ConverterErrorKind, Result};

#[derive(Deserialize)]
pub(crate) struct NitroEnclaveMeasurements {
    #[serde(rename(deserialize = "Measurements"))]
    pub(crate) pcr_list: PCRList,
}

#[derive(Deserialize)]
pub(crate) struct PCRList {
    #[serde(alias = "PCR0")]
    pub(crate) pcr0: String,
    #[serde(alias = "PCR1")]
    pub(crate) pcr1: String,
    #[serde(alias = "PCR2")]
    pub(crate) pcr2: String,
    /// Only present if enclave file is built with signing certificate
    #[serde(alias = "PCR8")]
    pub(crate) pcr8: Option<String>,
}

async fn create_nitro_image(
    image: &DockerReference<'_>,
    output_file: &Path,
) -> Result<NitroEnclaveMeasurements> {
    let output = output_file.to_str().ok_or(ConverterError {
        message: format!("Failed to cast path {:?} to string", output_file),
        kind: ConverterErrorKind::NitroFileCreation,
    })?;

    let image_as_str = image.to_string();

    let nitro_cli_args = [
        "build-enclave",
        "--docker-uri",
        &image_as_str,
        "--output-file",
        output,
    ];

    let process_output = run_subprocess("nitro-cli", &nitro_cli_args)
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::NitroFileCreation,
        })?;

    serde_json::from_str::<NitroEnclaveMeasurements>(&process_output).map_err(|err| {
        ConverterError {
            message: format!("Bad measurements. {:?}", err),
            kind: ConverterErrorKind::NitroFileCreation,
        }
    })
}

pub(crate) struct EnclaveImageBuilder<'a> {
    pub(crate) enclave_image_builder: crate::image_builder::enclave::EnclaveImageBuilder<'a>,
}

impl<'a> EnclaveImageBuilder<'a> {
    pub const ENCLAVE_FILE_NAME: &'static str = "enclave.eif";

    pub(crate) async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        enclave_settings: EnclaveSettings,
        user_config: UserConfig,
        env_vars: Vec<String>,
        images_to_clean_snd: Sender<ImageToClean>,
    ) -> Result<NitroEnclaveMeasurements> {
        let is_debug = enclave_settings.is_debug;
        let enable_overlay_filesystem_persistence =
            enclave_settings.enable_overlay_filesystem_persistence;
        let ccm_backend_url = enclave_settings.ccm_backend_url.clone();
        let dsm_configuration = enclave_settings.dsm_configuration.clone();

        let build_context =
            BuildContext::new(&self.enclave_image_builder.dir.path()).map_err(|message| {
                ConverterError {
                    message,
                    kind: ConverterErrorKind::RequisitesCreation,
                }
            })?;

        self.enclave_image_builder
            .create_requisites(enclave_settings, &build_context)
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        let file_system_config = self
            .enclave_image_builder
            .create_block_file(docker_util, &user_config)
            .await?;
        info!("Client FS Block file has been created.");

        let enclave_manifest = EnclaveManifest {
            user_config,
            file_system_config,
            is_debug,
            env_vars,
            enable_overlay_filesystem_persistence,
            ccm_backend_url,
            dsm_configuration,
        };

        crate::image_builder::enclave::EnclaveImageBuilder::create_manifest_file(
            enclave_manifest,
            &build_context,
        )?;

        info!("Enclave build prerequisites have been created!");

        let build_context_archive_file = build_context
            .package_into_archive(
                &self
                    .enclave_image_builder
                    .dir
                    .path()
                    .join("enclave-build-context.tar"),
            )
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        // This image is made temporary because it is only used by nitro-cli to create an `.eif` file.
        // After nitro-cli finishes we can safely reclaim it.
        let result_image_raw = self.enclave_image_builder.enclave_image();

        let result_reference =
            DockerReference::from_str(&result_image_raw).map_err(|message| ConverterError {
                message: format!("Failed to create enclave image reference. {:?}", message),
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        let result = docker_util
            .create_image_from_archive(result_reference, build_context_archive_file)
            .await
            .map(|e| e.make_temporary(ImageKind::Intermediate, images_to_clean_snd))
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::EnclaveImageCreation,
            })?;

        let nitro_measurements = {
            let nitro_image_path = &self
                .enclave_image_builder
                .dir
                .path()
                .join(EnclaveImageBuilder::ENCLAVE_FILE_NAME);

            create_nitro_image(&result.image.reference, &nitro_image_path).await?
        };

        info!("Nitro image has been created!");

        Ok(nitro_measurements)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};
    use std::path::{Path, PathBuf};

    use api_model::converter::{CertIssuer, CertificateConfig, KeyType};
    use api_model::enclave::{User, UserConfig, UserProgramConfig, WorkingDir};
    use rand::RngCore;
    use tar::{Archive, Builder};
    use tempfile::{NamedTempFile, TempDir};

    use crate::image_builder::enclave::{ArchiveExtensions, ArchiveSize, EnclaveImageBuilder};

    #[test]
    fn archive_size_add_zero_correct_pass() {
        let a = ArchiveSize {
            total_file_size: 1,
            dir_count: 2,
            file_count: 3,
        };

        let b = ArchiveSize::default();
        let result = a + b;

        assert_eq!(result.total_file_size, 1);
        assert_eq!(result.dir_count, 2);
        assert_eq!(result.file_count, 3);
    }

    #[test]
    fn archive_size_add_correct_pass() {
        let a = ArchiveSize {
            total_file_size: 1,
            dir_count: 1,
            file_count: 1,
        };

        let b = ArchiveSize {
            total_file_size: 1,
            dir_count: 2,
            file_count: 3,
        };

        let result = a + b;

        assert_eq!(result.total_file_size, 2);
        assert_eq!(result.dir_count, 3);
        assert_eq!(result.file_count, 4);
    }

    #[test]
    fn empty_archive_correct_pass() {
        use ArchiveExtensions;

        let archive_file = NamedTempFile::new_in("/tmp").expect("Failed creating archive file");

        let mut builder = Builder::new(archive_file);
        builder.finish().expect("failed building archive");

        let file = builder.into_inner().expect("Failed unwrapping builder");

        let mut archive = Archive::new(file);
        let result = archive
            .size()
            .expect("Failed computing size of the archive");

        assert_eq!(result, 0)
    }

    #[test]
    fn dir_and_file_archive_correct_pass() {
        use ArchiveExtensions;

        let archive_file =
            NamedTempFile::new_in(Path::new("/tmp")).expect("Failed creating archive file");
        let mut data_file_a =
            NamedTempFile::new_in(Path::new("/tmp")).expect("Failed creating data file");

        let test_data = "Hello World";
        data_file_a
            .write_all(test_data.as_bytes())
            .expect("Failed writing test data");
        data_file_a.rewind().expect("Failed rewinding file");

        let mut builder = Builder::new(archive_file);
        builder
            .append_dir("test-dir-a", "/")
            .expect("Failed appending dir to archive");
        builder
            .append_file("test-dir-a/file_a.txt", data_file_a.as_file_mut())
            .expect("Failed appending path to archive");

        let mut file = builder.into_inner().expect("Failed unwrapping builder");
        file.rewind().expect("Failed rewinding file");

        let mut archive = Archive::new(file);

        let result = archive
            .size()
            .expect("Failed computing size of the archive");
        let reference = ArchiveSize {
            total_file_size: test_data.as_bytes().len() as u64,
            dir_count: 1,
            file_count: 1,
        };

        assert_eq!(result, reference.size_bytes())
    }

    fn user_config(key_path: Option<String>, cert_path: Option<String>) -> UserConfig {
        UserConfig {
            user_program_config: UserProgramConfig {
                entry_point: "".to_string(),
                arguments: vec![],
                working_dir: WorkingDir::from(""),
                user: User::from(""),
                group: User::from(""),
            },
            certificate_config: vec![CertificateConfig {
                issuer: CertIssuer::ManagerCa,
                subject: None,
                alt_names: vec![],
                key_type: KeyType::Rsa,
                key_param: None,
                key_path,
                cert_path,
                chain_path: None,
            }],
        }
    }

    fn no_certs_user_config() -> UserConfig {
        UserConfig {
            user_program_config: UserProgramConfig {
                entry_point: "".to_string(),
                arguments: vec![],
                working_dir: WorkingDir::from(""),
                user: User::from(""),
                group: User::from(""),
            },
            certificate_config: vec![],
        }
    }

    fn abs_non_existent_path() -> PathBuf {
        non_existent_path(Path::new("/path/to/some/file"))
    }

    fn relative_non_existent_path() -> PathBuf {
        non_existent_path(Path::new("path/to/some/file"))
    }

    fn non_existent_path(base_path: &Path) -> PathBuf {
        let mut rng = rand::thread_rng();
        let mut result = base_path.to_path_buf();

        while result.exists() {
            let random_number = rng.next_u32();
            result = base_path.join(random_number.to_string());
        }

        result
    }

    fn path_to_str(path: &Path) -> String {
        path.to_str().expect("path to str fail").to_string()
    }

    #[test]
    fn check_path_not_found_correct_path() {
        let abs_key_path = abs_non_existent_path();
        let abs_cert_path = abs_non_existent_path();
        let relative_key_path = relative_non_existent_path();
        let relative_cert_path = relative_non_existent_path();
        let no_file_path = Path::new("/");

        assert!(abs_cert_path.is_absolute());
        assert!(abs_cert_path.is_absolute());
        assert!(relative_key_path.is_relative());
        assert!(relative_cert_path.is_relative());

        let configs = vec![
            user_config(Some(path_to_str(&abs_key_path)), None),
            user_config(None, Some(path_to_str(&abs_cert_path))),
            user_config(
                Some(path_to_str(&abs_key_path)),
                Some(path_to_str(&abs_cert_path)),
            ),
            user_config(Some(path_to_str(&relative_key_path)), None),
            user_config(None, Some(path_to_str(&relative_cert_path))),
            user_config(
                Some(path_to_str(&relative_key_path)),
                Some(path_to_str(&relative_cert_path)),
            ),
            user_config(
                Some(path_to_str(&no_file_path)),
                Some(path_to_str(&no_file_path)),
            ),
            user_config(Some(String::new()), Some(String::new())),
        ];

        let block_file_valid_path = Path::new("/tmp");

        for config in &configs {
            assert!(
                EnclaveImageBuilder::check_path_exists(config, block_file_valid_path).is_err(),
                "Config used: {:?}",
                config
            )
        }

        let block_file_invalid_path = abs_non_existent_path();

        for config in &configs {
            assert!(
                EnclaveImageBuilder::check_path_exists(config, Path::new(&block_file_invalid_path))
                    .is_err(),
                "Config used: {:?}",
                config
            )
        }
    }

    #[test]
    fn check_path_empty_config_correct_path() {
        let configs = vec![user_config(None, None), no_certs_user_config()];

        for config in &configs {
            assert!(EnclaveImageBuilder::check_path_exists(config, Path::new("/tmp")).is_ok())
        }
    }

    #[test]
    fn check_path_found_correct_path() {
        let block_file_valid_path = Path::new("/tmp");
        let key_file_dir =
            TempDir::new_in(block_file_valid_path).expect("Failed creating key file dir");
        let cert_file_dir =
            TempDir::new_in(block_file_valid_path).expect("Failed creating cert file dir");

        let abs_key_path = {
            let result = key_file_dir
                .path()
                .strip_prefix("/tmp")
                .unwrap()
                .join("key.pem");
            Path::new("/").join(result)
        };
        let abs_cert_path = {
            let result = cert_file_dir
                .path()
                .strip_prefix("/tmp")
                .unwrap()
                .join("cert.pem");
            Path::new("/").join(result)
        };

        assert!(abs_key_path.is_absolute());
        assert!(abs_cert_path.is_absolute());

        let relative_key_path = key_file_dir
            .path()
            .strip_prefix("/tmp/")
            .unwrap()
            .join("key.pem");
        let relative_cert_path = cert_file_dir
            .path()
            .strip_prefix("/tmp/")
            .unwrap()
            .join("cert.pem");

        assert!(relative_key_path.is_relative());
        assert!(relative_cert_path.is_relative());

        let configs = vec![
            user_config(Some(path_to_str(&abs_key_path)), None),
            user_config(None, Some(path_to_str(&abs_cert_path))),
            user_config(
                Some(path_to_str(&abs_key_path)),
                Some(path_to_str(&abs_cert_path)),
            ),
            user_config(Some(path_to_str(&relative_key_path)), None),
            user_config(None, Some(path_to_str(&relative_cert_path))),
            user_config(
                Some(path_to_str(&relative_key_path)),
                Some(path_to_str(&relative_cert_path)),
            ),
        ];

        for config in &configs {
            assert!(
                EnclaveImageBuilder::check_path_exists(config, block_file_valid_path).is_ok(),
                "Config used: {:?}",
                config
            )
        }
    }
}
