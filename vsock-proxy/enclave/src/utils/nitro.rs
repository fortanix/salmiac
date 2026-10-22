/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::borrow::Cow;

use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver,
};
use ftx_cert_build::{Csr, NameBuilder};
use mbedtls::{
    pk::{Pk, Type as PkType},
    rng::{Random, Rdrand},
};
use pkix::{
    pem::{der_to_pem, PEM_CERTIFICATE_REQUEST},
    types::{Attribute, EcdsaX962, GeneralName, Name, RsaPkcs15, Sha256},
    ToDer,
};
use sha2::{Digest, Sha256 as Sha256Digest};

pub(crate) fn common_name_to_subject(common_name: &str) -> Name {
    NameBuilder::new().add_common_name(common_name).build_name()
}

fn get_user_data(pub_key: &[u8], config_id: Option<&str>) -> Result<[u8; 64], String> {
    let mut data = [0; 64];
    data[..32].copy_from_slice(&Sha256Digest::digest(pub_key));
    if let Some(id) = config_id {
        let id = hex::decode(id).map_err(|err| err.to_string())?;
        if id.len() != 32 {
            return Err("config ID must be 32 bytes".into());
        }
        let mut payload = [0; 65];
        payload[0] = 1;
        payload[1..33].copy_from_slice(&data[..32]);
        payload[33..].copy_from_slice(&id[..32]);

        // The payload is formed as follows in case of workflow report.
        // First 32 bytes is a Sha256 of (Version + public key sha256 + config-id)
        // Second 32 bytes part is the actual config-id.
        data[..32].copy_from_slice(&Sha256Digest::digest(&payload));
        data[32..].copy_from_slice(&id[..32]);
    }
    // if non-workflow report then first 32 bytes is the hash of the public key, second 32 bytes are all 0.

    Ok(data)
}

pub(crate) fn get_remote_attestation_csr_subject(
    subject: &Name,
    signer: &mut Pk,
    alt_names: Option<Vec<Cow<'_, str>>>,
    config_id: Option<&str>,
) -> Result<String, String> {
    let pub_key = signer.write_public_der_vec().map_err(|e| e.to_string())?;
    let user_data = get_user_data(&pub_key, config_id)?;
    let csr_pem = get_attestation_parameters_subject(signer, subject, &user_data, alt_names)?;
    Ok(csr_pem)
}

pub(crate) fn get_attestation_parameters_subject(
    signer: &mut Pk,
    subject: &Name,
    user_data: &[u8; 64],
    alt_names: Option<Vec<Cow<'_, str>>>,
) -> Result<String, String> {
    let document = get_attestation(user_data)?;
    let csr_pem = get_csr(subject, signer, document, alt_names)?;
    Ok(csr_pem)
}

/// Request a Nitro attestation document bound to the supplied user data.
pub(crate) fn get_attestation(user_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    let mut nonce = [0; 16];
    Rdrand
        .random(&mut nonce)
        .map_err(|e| format!("Failed generating nonce: {}", e))?;
    let nsm_fd = driver::nsm_init();
    let response = driver::nsm_process_request(
        nsm_fd,
        Request::Attestation {
            public_key: None,
            user_data: Some(serde_bytes::ByteBuf::from(user_data.to_vec())),
            nonce: Some(serde_bytes::ByteBuf::from(nonce.to_vec())),
        },
    );
    driver::nsm_exit(nsm_fd);
    let document = match response {
        Response::Attestation { document } => document,
        Response::Error(e) => {
            return Err(format!(
                "Failed getting attestation from nsm_driver: {:?}",
                e
            ))
        }
        other => return Err(format!("Unknown response from nsm_driver: {:?}", other)),
    };
    Ok(document)
}

fn get_csr(
    subject: &Name,
    signer: &mut Pk,
    document: Vec<u8>,
    alt_names: Option<Vec<Cow<'_, str>>>,
) -> Result<String, String> {
    let attestation = document.to_der();
    let mut builder = Csr::mbedtls_crypto_builder()
        .with_subject(subject.clone().into())
        .with_attributes(vec![Attribute {
            oid: vme_pkix::oid::ATTESTATION_NITRO.clone(),
            value: vec![attestation.into()],
        }])
        .map_err(|e| e.to_string())?;
    if let Some(names) = alt_names {
        builder = builder
            .with_san_extension_from_general_names(names.into_iter().map(GeneralName::DnsName));
    }
    // Unlike em-app's Nitro CSR builder, which omitted basicConstraints,
    // ftx-cert-build always requests this critical extension (CA=false by default).
    let csr = match signer.pk_type() {
        PkType::Rsa => builder
            .with_self_signing_key(signer, RsaPkcs15(Sha256))
            .and_then(|builder| builder.build_csr()),
        PkType::Eckey | PkType::Ecdsa => builder
            .with_self_signing_key(signer, EcdsaX962(Sha256))
            .and_then(|builder| builder.build_csr()),
        other => return Err(format!("Invalid key type: {:?}", other)),
    }
    .map_err(|e| format!("Failed building CSR: {}", e))?;
    Ok(der_to_pem(&*csr, PEM_CERTIFICATE_REQUEST))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkix::yasna;

    #[test]
    fn report_data_binds_key_and_configuration() {
        let key = b"public key";
        let plain = get_user_data(key, None).unwrap();
        assert_eq!(&plain[..32], Sha256Digest::digest(key).as_slice());
        assert_eq!(&plain[32..], &[0; 32]);

        let id = "ab".repeat(32);
        let workflow = get_user_data(key, Some(&id)).unwrap();
        let mut payload = vec![1];
        payload.extend_from_slice(&plain[..32]);
        payload.extend_from_slice(&[0xab; 32]);
        assert_eq!(&workflow[..32], Sha256Digest::digest(&payload).as_slice());
        assert_eq!(&workflow[32..], &[0xab; 32]);
        assert_eq!(
            workflow,
            get_user_data(key, Some(&id.to_uppercase())).unwrap()
        );
        for invalid in ["", "ab", &"gg".repeat(32), &"é".repeat(32)] {
            assert!(get_user_data(key, Some(invalid)).is_err());
        }
    }

    #[test]
    fn csr_embeds_nitro_attestation_document() {
        use pkix::{pem::pem_to_der, pkcs10::DerCertificationRequest, FromDer};

        let mut key = Pk::generate_rsa(&mut Rdrand, 2048, 65537).unwrap();
        let document = vec![1, 2, 3];
        let pem = get_csr(
            &common_name_to_subject("example.com"),
            &mut key,
            document.clone(),
            None,
        )
        .unwrap();
        let der = pem_to_der(&pem, Some(PEM_CERTIFICATE_REQUEST)).unwrap();
        let csr = DerCertificationRequest::from_der(&der).unwrap();
        let attributes = csr
            .reqinfo
            .attributes
            .iter()
            .filter(|attribute| attribute.oid == *vme_pkix::oid::ATTESTATION_NITRO)
            .collect::<Vec<_>>();
        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].value.len(), 1);
        let decoded =
            yasna::parse_der(attributes[0].value[0].as_ref(), |r| r.read_bytes()).unwrap();
        assert_eq!(decoded, document);
    }
}
