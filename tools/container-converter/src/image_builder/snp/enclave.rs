use api_model::snp::SNPEnclavesMeasurements;
use docker_image_reference::Reference as DockerReference;
use tempfile::TempDir;

use crate::Result;

pub(crate) struct EnclaveImageBuilder<'a> {
    pub(crate) client_image_reference: &'a DockerReference<'a>,
    pub(crate) dir: &'a TempDir,
    pub(crate) enclave_base_image: &'a DockerReference<'a>,
}
impl<'a> EnclaveImageBuilder<'a> {
    // TODO: RTE-941
    pub(crate) async fn create_image(
        &self,
        input_repository: &crate::docker::DockerDaemon,
        enclave_settings: crate::image_builder::enclave::EnclaveSettings,
        user_config: api_model::enclave::UserConfig,
        image_env_vars: Vec<String>,
        sender: std::sync::mpsc::Sender<crate::image::ImageToClean>,
    ) -> Result<SNPEnclavesMeasurements> {
        todo!()
    }
}
