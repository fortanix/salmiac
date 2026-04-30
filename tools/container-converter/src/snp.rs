/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::{
    env,
    sync::mpsc::{self, Sender},
};

use api_model::{
    enclave::UserConfig,
    snp::{SNPEnclavesConversionRequest, SNPEnclavesConversionResponse},
    HexString,
};
use log::{debug, info};
use shiplift::Docker;
use tempfile::TempDir;

use crate::{
    clean_docker_images, create_user_program_config,
    docker::{DockerDaemon, DockerUtil},
    get_enclave_base_image, get_parent_base_image,
    image::{docker_reference, output_docker_reference, ImageKind, ImageToClean, ImageWithDetails},
    image_builder::{
        enclave::{get_image_env, EnclaveSettings},
        snp::enclave::EnclaveImageBuilder,
        snp::parent::ParentImageBuilder,
    },
    preserve_images_list, push_result_image, validate_request, ConverterError, ConverterErrorKind,
    Result, ENCLAVE_IMAGE, PARENT_IMAGE,
};

pub async fn run(args: SNPEnclavesConversionRequest) -> Result<SNPEnclavesConversionResponse> {
    let (images_to_clean_snd, images_to_clean_rcv) = mpsc::channel();
    let local_repository = Docker::new();
    let preserve_images = preserve_images_list()?;

    let resource_cleaner = tokio::spawn(clean_docker_images(
        local_repository,
        images_to_clean_rcv,
        preserve_images,
    ));
    let converter = tokio::spawn(run0(args, images_to_clean_snd));

    let (result, _) = tokio::join!(converter, resource_cleaner);

    result.map_err(|err| ConverterError {
        message: format!("Join error in convert task. {:?}", err),
        kind: ConverterErrorKind::InternalError,
    })?
}

async fn run0(
    conversion_request: SNPEnclavesConversionRequest,
    images_to_clean_snd: Sender<ImageToClean>,
) -> Result<SNPEnclavesConversionResponse> {
    // TODO: common code
    validate_request(&conversion_request.request)?;

    let parent_image = env::var("PARENT_IMAGE").unwrap_or(PARENT_IMAGE.to_string());
    info!("Parent base image is {}", parent_image);
    info!("Retrieving requisite images!");
    get_parent_base_image(&parent_image).await?;

    let client_image = docker_reference(&conversion_request.request.input_image.name)?;

    let input_repository = DockerDaemon::new(&conversion_request.request.input_image.auth_config);

    info!("Retrieving client image!");
    let input_image = input_repository
        .get_latest_image_details(&client_image)
        .await
        .map(|details| {
            ImageWithDetails {
                reference: client_image,
                details,
            }
            .make_temporary(ImageKind::Input, images_to_clean_snd.clone())
        })
        .map_err(|message| ConverterError {
            message,
            kind: ConverterErrorKind::ImageGet,
        })?;

    info!("Creating working directory!");
    let temp_dir = TempDir::new().map_err(|err| ConverterError {
        message: format!("Cannot create temp dir {:?}", err),
        kind: ConverterErrorKind::RequisitesCreation,
    })?;

    info!("Building enclave image!");
    let image_result = {
        let enclave_base_image_str = env::var("ENCLAVE_IMAGE").unwrap_or(ENCLAVE_IMAGE.to_string());
        info!("Enclave base image is {}", enclave_base_image_str);

        let enclave_base_image = get_enclave_base_image(&enclave_base_image_str).await?;

        let user_program_config = create_user_program_config(
            &conversion_request.request.converter_options,
            &input_image.image,
        )?;

        debug!("User program config is: {:?}", user_program_config);

        let enclave_settings =
            EnclaveSettings::new(&input_image, &conversion_request.request.converter_options);
        let image_env_vars =
            get_image_env(&input_image, &conversion_request.request.converter_options);
        let user_config = UserConfig {
            user_program_config,
            certificate_config: conversion_request.request.converter_options.certificates,
        };

        // End of common code - Move enclave builder down?
        let enclave_builder = EnclaveImageBuilder {
            client_image_reference: &input_image.image.reference,
            dir: &temp_dir,
            enclave_base_image: &enclave_base_image.reference,
        };

        let sender = images_to_clean_snd.clone();
        enclave_builder
            .create_image(
                &input_repository,
                enclave_settings,
                user_config,
                image_env_vars,
                sender,
            )
            .await?
    };

    let parent_builder = ParentImageBuilder {
        parent_image,
        dir: &temp_dir,
        start_options: conversion_request.snp_enclaves_options,
    };

    info!("Building result image!");
    let output_image = output_docker_reference(&conversion_request.request.output_image.name)?;
    let result = parent_builder
        .create_image(&input_repository, output_image)
        .await
        .map(|e| e.make_temporary(ImageKind::Result, images_to_clean_snd.clone()))?;

    if conversion_request
        .request
        .converter_options
        .push_converted_image
        .unwrap_or(true)
    {
        info!("Attempting to push output image");
        push_result_image(
            &result.image,
            &conversion_request.request.output_image.auth_config,
        )
        .await?;
    } else {
        info!("Skipping output image push");
    }

    create_response(&result.image, image_result.launch_measurement)
}

fn create_response(
    image: &ImageWithDetails,
    measurement: HexString,
) -> Result<SNPEnclavesConversionResponse> {
    todo!()
}
