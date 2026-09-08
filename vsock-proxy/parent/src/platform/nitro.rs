/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use log::info;
use shared::run_subprocess;

use super::{
    env_var_or_default, is_enclaveos_debug_enabled, GuestLaunchResult, GuestTasks,
    ENCLAVEOS_DEBUG_ENV,
};

const DEFAULT_CPU_COUNT: u8 = 2;
const DEFAULT_MEMORY_SIZE: u64 = 2048;

const CPU_COUNT_ENV: &str = "CPU_COUNT";
const MEM_SIZE_ENV: &str = "MEM_SIZE";

const NITRO_CLI: &str = "nitro-cli";
const ENCLAVE_NAME: &str = "enclave";
const EIF_PATH: &str = "/opt/fortanix/enclave-os/enclave.eif";

pub(crate) fn should_forward_client_logs() -> bool {
    !is_enclaveos_debug_enabled()
}

pub(crate) fn launch_guest() -> Result<GuestLaunchResult, String> {
    Ok(GuestLaunchResult {
        enclave_process: tokio::spawn(start_nitro_enclave()),
    })
}

pub(crate) fn start_post_connect_guest_tasks() -> GuestTasks {
    let tasks = GuestTasks::new();

    if is_enclaveos_debug_enabled() {
        tasks.push(tokio::spawn(stream_console_logs()));
    }

    tasks
}

async fn stream_console_logs() -> Result<(), String> {
    info!("{ENCLAVEOS_DEBUG_ENV} set, fetching enclave console logs.");

    run_subprocess(
        NITRO_CLI,
        &[
            "console",
            "--enclave-name",
            ENCLAVE_NAME,
            "--disconnect-timeout",
            "30",
        ],
    )
    .await
}

async fn start_nitro_enclave() -> Result<(), String> {
    let cpu_count = env_var_or_default(CPU_COUNT_ENV, DEFAULT_CPU_COUNT);
    let memsize = env_var_or_default(MEM_SIZE_ENV, DEFAULT_MEMORY_SIZE);

    let mut args = vec![
        "run-enclave",
        "--eif-path",
        EIF_PATH,
        "--cpu-count",
        &cpu_count,
        "--memory",
        &memsize,
    ];

    if is_enclaveos_debug_enabled() {
        args.push("--debug-mode");
    }

    run_subprocess(NITRO_CLI, &args).await
}
