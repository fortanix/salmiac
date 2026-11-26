/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use crate::image_builder::enclave::qemu::DEFAULT_PATH;
use crate::image_builder::enclave::EnclaveEnvVars;

pub(crate) const NVIDIA_DRIVER_LIBRARY_PATH: &str = "/opt/fortanix/nvidia-driver/lib";
pub(crate) const NVIDIA_DRIVER_BINARY_PATH: &str = "/opt/fortanix/nvidia-driver/bin";
pub(crate) const NVIDIA_DRIVER_FIRMWARE_PAYLOAD_ROOT: &str =
    "/opt/fortanix/enclave-os/nvidia-driver-payload/firmware";

pub(crate) const KERNEL_MODULES: &[&str] = &[
    "nvidia.ko",
    "nvidia-uvm.ko",
    "nvidia-drm.ko",
    "nvidia-modeset.ko",
];

pub(crate) fn insert_nvidia_env_vars(
    env_vars: &mut EnclaveEnvVars,
    driver_capabilities: &Vec<String>,
) {
    prepend_env(
        env_vars,
        "LD_LIBRARY_PATH",
        NVIDIA_DRIVER_LIBRARY_PATH,
        None,
    );
    prepend_env(
        env_vars,
        "PATH",
        NVIDIA_DRIVER_BINARY_PATH,
        Some(DEFAULT_PATH),
    );
    upsert_env(
        env_vars,
        "NVIDIA_DRIVER_CAPABILITIES",
        &driver_capabilities.join(","),
    );
}

fn prepend_env(env_vars: &mut EnclaveEnvVars, key: &str, prefix: &str, default: Option<&str>) {
    let current = env_vars
        .image_env_vars
        .get(key)
        .map(|value| value.clone())
        .or_else(|| default.map(|value| value.to_string()))
        .unwrap_or_default();

    let value = if current.is_empty() {
        prefix.to_string()
    } else if current.split(':').any(|entry| entry == prefix) {
        current
    } else {
        format!("{}:{}", prefix, current)
    };

    upsert_env(env_vars, key, &value);
}

/// Insert or update the entries for a specific key in the enclave variables.
fn upsert_env(env_vars: &mut EnclaveEnvVars, key: &str, value: &str) {
    // Only update the manifest if it already had this variable in it
    if let Some(config) = env_vars.manifest_env_vars.get_mut(key) {
        config.value = Some(value.to_string());
    }
    // Upsert the hash map with env var values
    env_vars
        .image_env_vars
        .insert(key.to_string(), value.to_string());
}
