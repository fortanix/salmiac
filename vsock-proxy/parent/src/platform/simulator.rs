/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use super::{GuestLaunchResult, GuestTasks};
use crate::platform::qemu::{constants, env_or_default, QemuPlatform};

const DEFAULT_MEMORY_SIZE: &str = "2048M";

struct SimulatorPlatform;

impl QemuPlatform for SimulatorPlatform {
    fn firmware_path(&self) -> Option<&'static str> {
        None
    }

    fn host_cc_device_paths(&self) -> Vec<&'static str> {
        Vec::new()
    }

    fn cpu(&self) -> String {
        "host".to_owned()
    }

    // Simulator is mostly used locally; setting a reasonable default.
    fn memory_size(&self) -> String {
        env_or_default(constants::MEM_SIZE_ENV_VAR, DEFAULT_MEMORY_SIZE)
    }

    fn machine(&self) -> Option<String> {
        None
    }

    fn objects(&self) -> Vec<String> {
        Vec::new()
    }

    fn gpu(&self) -> Option<String> {
        None
    }
}

pub(crate) fn should_forward_client_logs() -> bool {
    true
}

pub(crate) fn launch_guest() -> GuestLaunchResult {
    let enclave_process = tokio::spawn(start_simulator_guest());

    GuestLaunchResult { enclave_process }
}

pub(crate) fn start_post_connect_guest_tasks() -> GuestTasks {
    GuestTasks::new()
}

async fn start_simulator_guest() -> Result<(), String> {
    SimulatorPlatform.run().await
}
