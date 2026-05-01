use api_model::snp::SNPEnclavesConversionRequestOptions;
use tempfile::TempDir;

use crate::{image::ImageWithDetails, Result};

pub(crate) struct ParentImageBuilder<'a> {
    pub(crate) parent_image: String,
    pub(crate) dir: &'a TempDir,
    pub(crate) start_options: SNPEnclavesConversionRequestOptions,
}
impl<'a> ParentImageBuilder<'a> {
    // TODO: RTE-941
    pub(crate) async fn create_image(
        &self,
        input_repository: &crate::docker::DockerDaemon,
        output_image: docker_image_reference::Reference<'_>,
    ) -> Result<ImageWithDetails<'a>> {
        todo!()
    }
}
