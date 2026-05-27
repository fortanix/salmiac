/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::OsString;
use std::path::Path;

use api_model::snp::SNPEnclavesMeasurements;
use api_model::HexString;

use crate::{run_subprocess, ConverterError, ConverterErrorKind, Result};

const MEASURE_SCRIPT: &str = "/opt/sev-snp-measure/measure.py";

pub(crate) struct SnpMeasurementInputs<'a> {
    pub ovmf: &'a Path,
    pub kernel: &'a Path,
    pub initrd: Option<&'a Path>,
    pub cmdline: Option<&'a str>,
    pub vcpus: u8,
}

pub(crate) async fn compute_snp_launch_measurement(
    inputs: &SnpMeasurementInputs<'_>,
) -> Result<SNPEnclavesMeasurements> {
    let mut args: Vec<OsString> = vec![
        "--ovmf".into(),
        inputs.ovmf.as_os_str().to_os_string(),
        "--kernel".into(),
        inputs.kernel.as_os_str().to_os_string(),
        "--vcpus".into(),
        inputs.vcpus.to_string().into(),
    ];
    if let Some(initrd) = inputs.initrd {
        args.push("--initrd".into());
        args.push(initrd.as_os_str().to_os_string());
    }
    if let Some(cmdline) = inputs.cmdline {
        args.push("--cmdline".into());
        args.push(cmdline.into());
    }

    let stdout = run_subprocess(MEASURE_SCRIPT, &args)
        .await
        .map_err(|message| ConverterError {
            message: format!("Failed to compute SNP launch measurement: {}", message),
            kind: ConverterErrorKind::EnclaveImageCreation,
        })?;

    let hex = stdout.trim();
    let launch_measurement = HexString::from_str(hex).map_err(|err| ConverterError {
        message: format!(
            "measure.py produced an invalid hex measurement {:?}: {}",
            hex, err
        ),
        kind: ConverterErrorKind::EnclaveImageCreation,
    })?;

    Ok(SNPEnclavesMeasurements { launch_measurement })
}
