/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::path::Path;

use shared::run_subprocess;

use super::{GuestLaunchResult, GuestTasks};

const QEMU_BINARY: &str = "qemu-system-x86_64";

const KERNEL_PATH: &str = "/opt/fortanix/enclave-os/kernel";
const INITRAMFS_PATH: &str = "/opt/fortanix/enclave-os/initramfs.cpio.gz";

const CPU_COUNT: &str = "2";
const MEMORY_SIZE: &str = "2048";

const KERNEL_CMDLINE: &str = "console=ttyS0 rdinit=/init loglevel=7";

pub(crate) fn should_forward_client_logs() -> bool {
    true
}

pub(crate) fn launch_guest() -> GuestLaunchResult {
    let enclave_process = tokio::spawn(start_simulator_guest());

    GuestLaunchResult {
        enclave_process,
    }
}

pub(crate) fn start_post_connect_guest_tasks() -> GuestTasks {
    GuestTasks::new()
}


async fn start_simulator_guest() -> Result<(), String> {
    require_file("simulator kernel", KERNEL_PATH)?;
    require_file("simulator initramfs", INITRAMFS_PATH)?;
    require_file("KVM device", "/dev/kvm")?;

    let args = [
        "-enable-kvm",
        "-cpu",
        "host",
        "-m",
        MEMORY_SIZE,
        "-smp",
        CPU_COUNT,
        "-display",
        "none",
        "-serial",
        "telnet:0.0.0.0:4321,server,wait",
        "-monitor",
        "none",
        "-no-reboot",
        "-kernel",
        KERNEL_PATH,
        "-initrd",
        INITRAMFS_PATH,
        "-append",
        KERNEL_CMDLINE,
        "-device",
        "vhost-vsock-pci,guest-cid=3"
    ];

    run_subprocess(
        QEMU_BINARY,
        &args,
    )
    .await
}

fn require_file(description: &str, path: &str) -> Result<(), String> {
    if Path::new(path).exists() {
        Ok(())
    } else {
        Err(format!("{description} not found at {path}"))
    }
}
