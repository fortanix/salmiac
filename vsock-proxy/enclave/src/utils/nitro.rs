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
use mbedtls::{
    hash,
    pk::{Pk, Type as PkType},
    rng::{Random, Rdrand},
};
use pkix::{
    bit_vec::BitVec,
    pem::{der_to_pem, PEM_CERTIFICATE_REQUEST},
    pkcs10::{CertificationRequest, CertificationRequestInfo},
    types::{Attribute, DerSequence, EcdsaX962, Extension, GeneralName, Name, RsaPkcs15, Sha256},
    x509::SubjectAltName,
    yasna::{self, models::TaggedDerValue, tags::TAG_UTF8STRING},
    DerWrite, ToDer,
};
use sha2::{Digest, Sha256 as Sha256Digest};

pub(crate) fn common_name_to_subject(common_name: &str) -> Name {
    vec![(
        pkix::oid::commonName.clone(),
        TaggedDerValue::from_tag_and_bytes(TAG_UTF8STRING, common_name.as_bytes().to_vec()),
    )]
    .into()
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
    let csr_pem =
        get_attestation_parameters_subject(signer, subject, &user_data, alt_names)?;
    Ok(csr_pem)
}

/// Nitro returns the attested CSR without separate attestation or node certificates.
pub(crate) fn get_attestation_parameters_subject(
    signer: &mut Pk,
    subject: &Name,
    user_data: &[u8; 64],
    alt_names: Option<Vec<Cow<'_, str>>>,
) -> Result<String, String> {
    let document = get_attestation(user_data)?;
    let pub_key = signer.write_public_der_vec().map_err(|e| e.to_string())?;
    let csr_pem = get_csr(subject, signer, &pub_key, document, alt_names)?;
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
    pub_key: &[u8],
    document: Vec<u8>,
    alt_names: Option<Vec<Cow<'_, str>>>,
) -> Result<String, String> {
    let attestation = document.to_der();
    let mut attributes = vec![Attribute {
        oid: vme_pkix::oid::ATTESTATION_NITRO.clone(),
        value: vec![attestation.as_slice().into()],
    }];
    let extensions;
    if let Some(names) = alt_names {
        extensions = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                Extension {
                    oid: pkix::oid::subjectAltName.clone(),
                    critical: false,
                    value: yasna::construct_der(|w| {
                        SubjectAltName {
                            names: names
                                .into_iter()
                                .map(GeneralName::DnsName)
                                .collect::<Vec<_>>()
                                .into(),
                        }
                        .write(w)
                    }),
                }
                .write(w.next());
            })
        });
        attributes.push(Attribute {
            oid: pkix::oid::extensionRequest.clone(),
            value: vec![extensions.as_slice().into()],
        });
    }
    let reqinfo = DerSequence::from(yasna::construct_der(|w| {
        CertificationRequestInfo {
            subject: subject.clone(),
            spki: DerSequence::from(pub_key),
            attributes,
        }
        .write(w);
    }));
    let digest = Sha256Digest::digest(reqinfo.as_ref());
    let mut sig = vec![0; ((signer.len() + 7) / 8).max(mbedtls::pk::ECDSA_MAX_LEN)];
    let len = signer
        .sign(hash::Type::Sha256, &digest, &mut sig, &mut Rdrand)
        .map_err(|e| format!("Failed signing CSR: {}", e))?;
    sig.truncate(len);
    let sig = BitVec::from_bytes(&sig);
    let csr = match signer.pk_type() {
        PkType::Rsa | PkType::RsaAlt | PkType::RsassaPss => yasna::construct_der(|w| {
            CertificationRequest {
                reqinfo,
                sigalg: RsaPkcs15(Sha256),
                sig,
            }
            .write(w)
        }),
        PkType::Eckey | PkType::Ecdsa => yasna::construct_der(|w| {
            CertificationRequest {
                reqinfo,
                sigalg: EcdsaX962(Sha256),
                sig,
            }
            .write(w)
        }),
        other => return Err(format!("Invalid key type: {:?}", other)),
    };
    Ok(der_to_pem(&csr, PEM_CERTIFICATE_REQUEST))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // Follow ftx-cert-build's CSR tests: verify the original request-info DER
    // with mbedTLS, and reject a modified digest.
    fn check_csr(mut key: Pk, subject: Name, alt_names: Option<Vec<Cow<'_, str>>>) {
        use pkix::{
            pem::pem_to_der,
            pkcs10::{DerCertificationRequest, ExtensionRequest},
            FromDer,
        };

        let public_key = key.write_public_der_vec().unwrap();
        let document = vec![1, 2, 3];
        let expected_names = alt_names.clone();
        let pem = get_csr(&subject, &mut key, &public_key, document.clone(), alt_names).unwrap();
        let der = pem_to_der(&pem, Some(PEM_CERTIFICATE_REQUEST)).unwrap();
        let csr = DerCertificationRequest::from_der(&der).unwrap();
        assert_eq!(csr.reqinfo.subject, subject);
        assert_eq!(csr.reqinfo.spki.as_ref(), public_key.as_slice());
        let expected_algorithm = match key.pk_type() {
            PkType::Rsa => RsaPkcs15(Sha256).to_der(),
            PkType::Eckey => EcdsaX962(Sha256).to_der(),
            other => panic!("Unexpected test key type: {:?}", other),
        };
        assert_eq!(csr.sigalg.as_ref(), expected_algorithm.as_slice());

        // Extract the exact signed bytes, avoiding a re-encoding of the request.
        let info = yasna::parse_der(&der, |reader| {
            reader.read_sequence(|reader| {
                let info = reader.next().read_der()?;
                reader.next().read_der()?;
                reader.next().read_bitvec()?;
                Ok(info)
            })
        })
        .unwrap();
        let mut verifier = Pk::from_public_key(&public_key).unwrap();
        let mut digest = Sha256Digest::digest(&info);
        let signature = csr.sig.to_bytes();
        verifier
            .verify(hash::Type::Sha256, &digest, &signature)
            .unwrap();
        digest[0] ^= 1;
        assert!(verifier
            .verify(hash::Type::Sha256, &digest, &signature)
            .is_err());

        let attestation = csr
            .reqinfo
            .attributes
            .iter()
            .find(|attribute| attribute.oid == *vme_pkix::oid::ATTESTATION_NITRO)
            .unwrap();
        assert_eq!(attestation.value.len(), 1);
        let decoded = yasna::parse_der(attestation.value[0].as_ref(), |r| r.read_bytes()).unwrap();
        assert_eq!(decoded, document);

        let extensions = csr.get_singular_attribute::<ExtensionRequest>();
        match expected_names {
            Some(names) => {
                let extensions = extensions.unwrap();
                assert_eq!(extensions.extensions.len(), 1);
                let san = extensions
                    .get_requested_extension::<SubjectAltName>()
                    .unwrap();
                let expected = names
                    .into_iter()
                    .map(GeneralName::DnsName)
                    .collect::<Vec<_>>();
                assert_eq!(san.names.0, expected);
                assert_eq!(csr.reqinfo.attributes.len(), 2);
            }
            None => {
                assert!(extensions.is_none());
                assert_eq!(csr.reqinfo.attributes.len(), 1);
            }
        }
    }

    #[test]
    fn rsa_csr_preserves_subject_attestation_and_san() {
        check_csr(
            Pk::generate_rsa(&mut Rdrand, 2048, 65537).unwrap(),
            common_name_to_subject("example.com"),
            Some(vec![
                Cow::Borrowed("example.com"),
                Cow::Borrowed("www.example.com"),
            ]),
        );
    }

    #[test]
    fn ec_csr_preserves_subject_attestation_and_san() {
        check_csr(
            Pk::generate_ec(&mut Rdrand, mbedtls::pk::EcGroupId::SecP256R1).unwrap(),
            common_name_to_subject("example.com"),
            Some(vec![Cow::Borrowed("example.com")]),
        );
    }

    #[test]
    fn csr_supports_empty_subject_and_optional_san() {
        for names in [None, Some(vec![])] {
            check_csr(
                Pk::generate_rsa(&mut Rdrand, 2048, 65537).unwrap(),
                Name::from(vec![]),
                names,
            );
        }
    }
}
