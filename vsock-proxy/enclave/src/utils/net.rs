use std::sync::Arc;

use api_model::enclave::CcmBackendUrl;
use em_client::models::ApplicationConfigSdkmsCredentials;
use em_client::client::Client as EmClient;
use hyper::client::{Client, Pool};
use hyper::net::HttpsConnector;
use hyper_rustls::TlsClient;
use sdkms::SdkmsClient;

use crate::app_configuration::EmAppCredentials;

// This the counterpart of how em_app configures tls connection.
// For the security reasons rustls's TlsClient should be configured
// in a similar fashion.
// Reference: https://github.com/fortanix/rust-sgx/blob/5d33ab498ec96a7a429816501287f790a2b5bcfe/em-app/src/utils.rs#L53
//
// `ca_cert_list`
// em_app sets to `AuthMode::Required` only when `ca_cert_list` is provided.
// For rustls, if `ca_cert_list` is not provided, rustls always do checks against the
// default CA list.
// Reference: https://docs.rs/crate/hyper-rustls/0.6.2/source/src/lib.rs#200
// To disable completely `DangerousClientConfig` must be used:
// Reference: https://docs.rs/crate/rustls/0.13.1/source/src/client/mod.rs#209
//
// Tls version 1.2
// em_app explicitly sets to tls version 1.2 However rustls by default expects
// tls 1.2 or 1.3.
// Reference: https://docs.rs/crate/rustls/0.13.1/source/src/client/mod.rs#144
//
// SNI configuration is ignored for now.
pub fn get_hyper_tls_connector(
    credentials: &EmAppCredentials,
) -> Result<HttpsConnector<TlsClient>, String> {
    let mut ssl = TlsClient::new();
    let tls_config = Arc::get_mut(&mut ssl.cfg)
        .expect("TlsClient config unexpectedly shared");

    if let Some(root_cert) = &credentials.root_certificate {
        for cert in root_cert {
            tls_config
                .root_store
                .add(cert)
                .map_err(|err| format!("Unable to add CCM root cert: {:?}", err))?;
        }
    }

    tls_config
        .set_single_client_cert(
            credentials.certificate.clone(),
            credentials.key.clone(),
        );

    Ok(HttpsConnector::new(ssl))
}

pub fn get_em_client(
    ccm_backend_url: &CcmBackendUrl,
    connector: HttpsConnector<TlsClient>,
) -> Result<EmClient, String> {
    let em_client = EmClient::try_new_with_connector(
            &ccm_backend_url.to_string(),
            Some("https"),
            connector,
        )
        .map_err(|err| format!("Unable to construct em_client: {}", err))?;
    Ok(em_client)
}

pub fn get_sdkms_client(
    sdkms_credentials: &ApplicationConfigSdkmsCredentials,
    connector: HttpsConnector<TlsClient>,
) -> Result<SdkmsClient, String> {
    let client = Arc::new(Client::with_connector(
        Pool::with_connector(Default::default(), connector),
    ));
    // em-client and sdkms use different versions of uuid.
    let app_id = sdkms_credentials.sdkms_app_id.to_string().parse()
        .map_err(|err| format!("Invalid SDKMS app ID: {}", err))?;
    let client = SdkmsClient::builder()
        .with_api_endpoint(&sdkms_credentials.credentials_url)
        .with_hyper_client(client)
        .build()
        .map_err(|err| format!("SDKMS Build failed: {:?}", err))?
        .authenticate_with_cert(Some(&app_id))
        .map_err(|err| format!("SDKMS authenticate failed: {:?}", err))?;
    Ok(client)
}
