use docker_image_reference::Reference as DockerReference;
use log::info;
use rand::distributions::{Alphanumeric, DistString};
use serde::Deserialize;
use tar::Archive;
use tempfile::TempDir;

use crate::docker::DockerUtil;
use crate::file::{DockerCopyArgs, DockerFile, Resource};
use crate::image_builder::{rust_log_env_var, INSTALLATION_DIR};
use crate::run_subprocess;
use crate::Result;
use crate::{file, ConverterError, ConverterErrorKind};

use api_model::shared::{EnclaveManifest, FileSystemConfig, UserConfig};
use api_model::ConverterOptions;

use crate::image::{ImageKind, ImageToClean, ImageWithDetails};
use std::fs;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc::Sender;

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

pub(crate) async fn create_nitro_image(image: &DockerReference<'_>, output_file: &Path) -> Result<NitroEnclaveMeasurements> {
    let output = output_file.to_str().ok_or(ConverterError {
        message: format!("Failed to cast path {:?} to string", output_file),
        kind: ConverterErrorKind::NitroFileCreation,
    })?;

    let image_as_str = image.to_string();

    let nitro_cli_args = [
        "build-enclave".as_ref(),
        "--docker-uri".as_ref(),
        image_as_str.as_ref(),
        "--output-file".as_ref(),
        output.as_ref(),
    ];

    let process_output = run_subprocess("nitro-cli".as_ref(), &nitro_cli_args)
        .await
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::NitroFileCreation,
        })?;

    serde_json::from_str::<NitroEnclaveMeasurements>(&process_output).map_err(|err| ConverterError {
        message: format!("Bad measurements. {:?}", err),
        kind: ConverterErrorKind::NitroFileCreation,
    })
}

pub(crate) struct EnclaveSettings {
    user_name: String,

    pub(crate) env_vars: Vec<String>,

    is_debug: bool,
}

impl EnclaveSettings {
    pub(crate) fn new(input_image: &ImageWithDetails<'_>, converter_options: &ConverterOptions) -> Self {
        let env_vars = {
            let mut result = input_image.details.config.env.as_ref().map(|e| e.clone()).unwrap_or(vec![]);

            // Docker `ENV` assigns environment variables by the order of definition, thus making
            // latest definition of the same variable override previous definition.
            // We exploit this logic to override variables from the `input_image` with the values from `conversion_request`
            // by adding all `conversion_request` variables to the end of `env_vars` vector.
            for request_env in &converter_options.env_vars {
                result.push(request_env.clone());
            }

            result
        };

        EnclaveSettings {
            user_name: input_image.details.config.user.clone(),
            env_vars,
            is_debug: converter_options.debug.unwrap_or(false),
        }
    }
}

pub(crate) struct EnclaveBuilderResult {
    pub(crate) pcr_list: PCRList,
}

pub(crate) struct EnclaveImageBuilder<'a> {
    pub(crate) client_image_reference: &'a DockerReference<'a>,

    pub(crate) dir: &'a TempDir,

    pub(crate) enclave_base_image: Option<DockerReference<'a>>,
}

impl<'a> EnclaveImageBuilder<'a> {
    pub const ENCLAVE_FILE_NAME: &'static str = "enclave.eif";

    const DEFAULT_ENCLAVE_SETTINGS_FILE: &'static str = "enclave-settings.json";

    const BLOCK_FILE_SCRIPT_NAME: &'static str = "create-block-file.sh";

    const BLOCK_FILE_INPUT_DIR: &'static str = "enclave-fs";

    const BLOCK_FILE_MOUNT_DIR: &'static str = "block-file-mount";

    pub const BLOCK_FILE_OUT: &'static str = "Blockfile.ext4";

    pub const RW_BLOCK_FILE_OUT: &'static str = "Blockfile-rw.ext4";

    // 256 MB converted to bytes
    pub const RW_BLOCK_FILE_DEFAULT_SIZE: u64 = 256 * 1024 * 1024;

    const IMAGE_BUILD_DEPENDENCIES: &'static [Resource<'static>] = &[
        Resource {
            name: "enclave",
            data: include_bytes!("../resources/enclave/enclave"),
            is_executable: true,
        },
        Resource {
            name: "enclave-startup",
            data: include_bytes!("../resources/enclave/enclave-startup"),
            is_executable: true,
        },
    ];

    const IMAGE_COPY_DEPENDENCIES: &'static [&'static str] = &["enclave", "enclave-settings.json", "enclave-startup"];

    pub(crate) async fn create_image(
        &self,
        docker_util: &dyn DockerUtil,
        enclave_settings: EnclaveSettings,
        user_config: UserConfig,
        images_to_clean_snd: Sender<ImageToClean>,
    ) -> Result<EnclaveBuilderResult> {
        let is_debug = enclave_settings.is_debug;

        match &self.enclave_base_image {
            Some(enclave_base) if is_debug => {
                self.create_debug_client_image(enclave_base, docker_util).await?;
            }
            _ => {}
        }

        let build_context_dir = self.create_build_context_dir()?;

        self.create_requisites(enclave_settings, &build_context_dir)
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        let fs_root_hash = match &self.enclave_base_image {
            Some(_) => {
                let root_hash = self.create_block_file(docker_util).await?;
                info!("Client FS Block file has been created.");

                self.create_rw_block_file().await?;
                info!("RW Block file has been created.");

                Some(root_hash)
            }
            _ => None,
        };

        let enclave_manifest = EnclaveManifest {
            user_config,
            file_system_config: fs_root_hash,
            is_debug,
        };

        self.create_manifest_file(enclave_manifest, &build_context_dir)?;

        info!("Enclave build prerequisites have been created!");

        let enclave_image_str = self.enclave_image();
        let enclave_image_reference = DockerReference::from_str(&enclave_image_str).map_err(|message| ConverterError {
            message: format!("Failed to create enclave image reference. {:?}", message),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        // This image is made temporary because it is only used by nitro-cli to create an `.eif` file.
        // After nitro-cli finishes we can safely reclaim it.
        let result = docker_util
            .create_image(enclave_image_reference, &build_context_dir)
            .await
            .map(|e| e.make_temporary(ImageKind::Intermediate, images_to_clean_snd))
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::EnclaveImageCreation,
            })?;

        let nitro_measurements = {
            let nitro_image_path = &self.dir.path().join(EnclaveImageBuilder::ENCLAVE_FILE_NAME);

            create_nitro_image(&result.image.reference, &nitro_image_path).await?
        };

        info!("Nitro image has been created!");

        Ok(EnclaveBuilderResult {
            pcr_list: nitro_measurements.pcr_list,
        })
    }

    async fn create_debug_client_image(
        &self,
        debug_enclave_base: &DockerReference<'_>,
        docker_util: &dyn DockerUtil,
    ) -> Result<()> {
        info!("Creating debug enclave image");

        let temp_dir = TempDir::new_in(self.dir.path()).map_err(|err| ConverterError {
            message: format!("Failed creating temp dir in {}. {:?}", self.dir.path().display(), err),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        let build_context_dir = temp_dir.path();

        self.create_debug_image_requisites(debug_enclave_base, &build_context_dir)
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::RequisitesCreation,
            })?;

        // To not change the behavior of `self.create_image` we overwrite client image inside a docker with
        // our debug extension by reusing the same reference in build function below.
        // This implicit behavior will be removed in: https://fortanix.atlassian.net/browse/SALM-273
        let image_reference = self.client_image_reference.to_string();
        let result = DockerReference::from_str(&image_reference).map_err(|message| ConverterError {
            message: format!("Failed to create enclave image reference. {:?}", message),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        let _ = docker_util
            .create_image(result, &build_context_dir)
            .await
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::EnclaveImageCreation,
            })?;

        Ok(())
    }

    pub(crate) async fn export_image_file_system(
        &self,
        docker_util: &dyn DockerUtil,
        archive_path: &Path,
        out_dir: &Path,
    ) -> Result<()> {
        let mut archive_file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&archive_path)
            .map_err(|err| ConverterError {
                message: format!("Failed creating image fs archive at {}. {:?}", archive_path.display(), err),
                kind: ConverterErrorKind::ImageFileSystemExport,
            })?;

        docker_util
            .export_image_file_system(&self.client_image_reference, &mut archive_file)
            .await
            .map_err(|message| ConverterError {
                message,
                kind: ConverterErrorKind::ImageFileSystemExport,
            })?;

        archive_file.rewind().map_err(|err| ConverterError {
            message: format!("Failed seek in image fs archive at {}. {:?}", archive_path.display(), err),
            kind: ConverterErrorKind::ImageFileSystemExport,
        })?;

        let mut tar = Archive::new(archive_file);
        tar.set_preserve_ownerships(true);

        tar.unpack(out_dir).map_err(|err| ConverterError {
            message: format!("Failed unpacking client fs archive {}. {:?}", out_dir.display(), err),
            kind: ConverterErrorKind::ImageFileSystemExport,
        })
    }

    fn create_build_context_dir(&self) -> Result<PathBuf> {
        let result = self.dir.path().join("enclave-build-context");

        fs::create_dir(&result).map_err(|err| ConverterError {
            message: format!("Failed creating dir {}. {:?}", result.display(), err),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        Ok(result)
    }

    fn create_manifest_file(&self, enclave_manifest: EnclaveManifest, dir: &Path) -> Result<()> {
        let data = serde_json::to_vec(&enclave_manifest).map_err(|err| ConverterError {
            message: format!("Failed serializing enclave settings file. {:?}", err),
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        let resource = [Resource {
            name: "enclave-settings.json",
            data: &data,
            is_executable: false,
        }];

        file::create_resources(&resource, dir).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })
    }

    async fn create_rw_block_file(&self) -> Result<()> {
        let block_file_out_path = self.dir.path().join(EnclaveImageBuilder::RW_BLOCK_FILE_OUT);

        let block_file = fs::File::create(&block_file_out_path).map_err(|err| ConverterError {
            message: format!("Failed creating RW block file {}. {:?}", block_file_out_path.display(), err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        block_file
            .set_len(EnclaveImageBuilder::RW_BLOCK_FILE_DEFAULT_SIZE)
            .map_err(|err| ConverterError {
                message: format!(
                    "Failed truncating RW block file {} to size {}. {:?}",
                    block_file_out_path.display(),
                    EnclaveImageBuilder::RW_BLOCK_FILE_DEFAULT_SIZE,
                    err
                ),
                kind: ConverterErrorKind::BlockFileCreation,
            })?;

        Ok(())
    }

    async fn create_block_file(&self, docker_util: &dyn DockerUtil) -> Result<FileSystemConfig> {
        let block_file_script = [Resource {
            name: EnclaveImageBuilder::BLOCK_FILE_SCRIPT_NAME,
            data: include_bytes!("../resources/fs/configure"),
            is_executable: true,
        }];

        file::create_resources(&block_file_script, self.dir.path()).map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::RequisitesCreation,
        })?;

        let block_file_input_dir = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_INPUT_DIR);
        let block_file_mount_dir = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_MOUNT_DIR);

        fs::create_dir(&block_file_input_dir).map_err(|err| ConverterError {
            message: format!("Failed creating dir {}. {:?}", block_file_input_dir.display(), err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        fs::create_dir(&block_file_mount_dir).map_err(|err| ConverterError {
            message: format!("Failed creating dir {}. {:?}", block_file_mount_dir.display(), err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        self.export_image_file_system(docker_util, &self.dir.path().join("fs.tar"), &block_file_input_dir)
            .await?;

        let result = {
            let block_file_out = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_OUT);
            let args = [
                block_file_input_dir.as_os_str(),
                block_file_mount_dir.as_os_str(),
                block_file_out.as_os_str(),
            ];
            let block_file_script_path = self.dir.path().join(EnclaveImageBuilder::BLOCK_FILE_SCRIPT_NAME);

            run_subprocess(block_file_script_path.as_os_str(), &args)
                .await
                .map_err(|message| ConverterError {
                    message,
                    kind: ConverterErrorKind::BlockFileCreation,
                })?
        };

        EnclaveImageBuilder::create_file_system_config(&result)
    }

    fn create_file_system_config(stdout: &str) -> Result<FileSystemConfig> {
        fn field_value(stdout: &str, field_start: usize) -> Option<&str> {
            stdout[field_start..]
                .find("\n")
                .map(|field_end| stdout[field_start..field_start + field_end].trim())
        }

        fn extract_value<'a>(stdout: &'a str, field_header: &str) -> Result<&'a str> {
            stdout
                .find(field_header)
                .and_then(|pos| field_value(stdout, pos + field_header.len()))
                .ok_or(ConverterError {
                    message: format!("Failed to find {} in stdout. Stdout: {}", field_header, stdout),
                    kind: ConverterErrorKind::BlockFileCreation,
                })
        }

        let root_hash = extract_value(stdout, "Root hash:")?;
        let raw_hash_offset = extract_value(stdout, "Hash offset:")?;

        let hash_offset = u64::from_str(raw_hash_offset).map_err(|err| ConverterError {
            message: format!("Failed to convert hash offset {} to int. {:?}", raw_hash_offset, err),
            kind: ConverterErrorKind::BlockFileCreation,
        })?;

        Ok(FileSystemConfig {
            root_hash: root_hash.to_string(),
            hash_offset,
        })
    }

    fn enclave_image(&self) -> String {
        let new_tag = self
            .client_image_reference
            .tag()
            .map(|e| e.to_string() + "-" + &Alphanumeric.sample_string(&mut rand::thread_rng(), 16))
            .unwrap_or("enclave".to_string());

        self.client_image_reference.name().to_string() + ":" + &new_tag
    }

    fn create_debug_image_requisites(
        &self,
        debug_enclave_base: &DockerReference,
        dir: &Path,
    ) -> std::result::Result<(), String> {
        let mut docker_file = file::create_docker_file(dir)?;

        // To inject debug utilities into the client image we create a composition of a `debug_enclave_base` and `self.client_image_reference`
        // by writing two `FROM` clauses into the Dockerfile and nothing else.
        // The resulting image's `ENTRYPOINT` will be the one from `debug_enclave_base` because it is written last
        let parent = self.client_image_reference.to_string();
        let child = debug_enclave_base.to_string();

        docker_file
            .write_all(DockerFile::<'_, &str, &str>::from(&parent).to_string().as_bytes())
            .map_err(|err| format!("Failed to write to Dockerfile {:?}", err))?;

        docker_file
            .write_all(DockerFile::<'_, &str, &str>::from(&child).to_string().as_bytes())
            .map_err(|err| format!("Failed to write to Dockerfile {:?}", err))?;

        if cfg!(debug_assertions) {
            file::log_docker_file(dir)?;
        }

        Ok(())
    }

    fn create_requisites(&self, enclave_settings: EnclaveSettings, dir: &Path) -> std::result::Result<(), String> {
        let mut docker_file = file::create_docker_file(dir)?;

        self.populate_docker_file(&mut docker_file, enclave_settings)?;

        if cfg!(debug_assertions) {
            file::log_docker_file(dir)?;
        }

        file::create_resources(EnclaveImageBuilder::IMAGE_BUILD_DEPENDENCIES, dir)?;

        Ok(())
    }

    fn populate_docker_file(&self, file: &mut fs::File, enclave_settings: EnclaveSettings) -> std::result::Result<(), String> {
        let install_dir_path = Path::new(INSTALLATION_DIR);

        let add = DockerCopyArgs {
            items: EnclaveImageBuilder::IMAGE_COPY_DEPENDENCIES,
            destination: INSTALLATION_DIR.to_string() + "/",
        };

        let run_enclave_cmd = {
            let enclave_bin = install_dir_path.join("enclave");

            let enclave_settings_file = install_dir_path.join(EnclaveImageBuilder::DEFAULT_ENCLAVE_SETTINGS_FILE);

            let user_name = {
                if let Some(pos) = enclave_settings.user_name.find(":") {
                    &enclave_settings.user_name[..pos]
                } else {
                    &enclave_settings.user_name
                }
            };

            // Quick fix for: https://fortanix.atlassian.net/browse/SALM-94
            // Sets the home variable specifically for applications that require it to run
            let switch_user_cmd = if user_name != "" && user_name != "root" {
                format!("export HOME=/home/{};", user_name)
            } else {
                String::new()
            };

            format!(
                "{} {} --vsock-port 5006 --settings-path {}",
                switch_user_cmd,
                enclave_bin.display(),
                enclave_settings_file.display()
            )
        };

        let client_image = &self.client_image_reference;
        let from = (match &self.enclave_base_image {
            Some(e) => e,
            _ => client_image,
        })
        .to_string();

        let mut env = enclave_settings.env_vars;
        env.push(rust_log_env_var("enclave"));

        let docker_file = DockerFile {
            from: &from,
            add: Some(add),
            env: &env,
            cmd: Some(&run_enclave_cmd),
            entrypoint: None,
        };

        file.write_all(docker_file.to_string().as_bytes())
            .map_err(|err| format!("Failed to write to Dockerfile {:?}", err))
    }
}
