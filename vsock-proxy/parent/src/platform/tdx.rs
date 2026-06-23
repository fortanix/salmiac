/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::env;

use super::{GuestLaunchResult, GuestTasks};
use crate::platform::qemu::QemuPlatform;

const OVMF_PATH: &str = "/opt/fortanix/enclave-os/OVMF.inteltdx.fd";
const GUEST_DEV_PATH: &str = "/dev/tdx_guest";
const MEMORY_BACKEND_ID: &str = "mem0";
const MEMORY_SIZE: &str = "8G";
const TDX_ID: &str = "tdx0";

struct TdxPlatform;

impl TdxPlatform {
    fn memory_backend() -> String {
        format!("memory-backend-ram,id={MEMORY_BACKEND_ID},size={MEMORY_SIZE}")
    }

    fn tdx_guest() -> String {
        format!("tdx-guest,id={TDX_ID}")
    }
}

impl QemuPlatform for TdxPlatform {
    fn firmware_path(&self) -> Option<&'static str> {
        Some(OVMF_PATH)
    }

    fn guest_device_path(&self) -> Option<&'static str> {
        Some(GUEST_DEV_PATH)
    }

    fn cpu(&self) -> String {
        env::var("TDX_CPU").unwrap_or_else(|_| "host".to_owned())
    }

    fn machine(&self) -> Option<String> {
        let machine = format!(
            "q35,kernel_irqchip=split,confidential-guest-support={TDX_ID},memory-backend={MEMORY_BACKEND_ID},hpet=off,smm=off,pic=off",
        );
        Some(machine)
    }

    fn objects(&self) -> Vec<String> {
        vec![Self::memory_backend(), Self::tdx_guest()]
    }

    fn gpu(&self) -> Option<String> {
        env::var("TDX_GPU_BDF").ok()
    }
}

pub(crate) fn should_forward_client_logs() -> bool {
    true
}

pub(crate) fn launch_guest() -> GuestLaunchResult {
    let enclave_process = tokio::spawn(start_tdx_guest());

    GuestLaunchResult { enclave_process }
}

pub(crate) fn start_post_connect_guest_tasks() -> GuestTasks {
    GuestTasks::new()
}

async fn start_tdx_guest() -> Result<(), String> {
    TdxPlatform.run().await
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_build_qemu_tdx_args() {
        // Ignore formatting to keep logical key/value pairs align better in a single line.
        #[rustfmt::skip]
        let expected = vec![
            "-enable-kvm", "-nographic", "-monitor", "none", "-no-reboot",
            "-machine", "q35,kernel_irqchip=split,confidential-guest-support=tdx0,memory-backend=mem0,hpet=off,smm=off,pic=off",
            "-cpu", "host", "-smp", "2", "-m", "8G",
            "-object", "memory-backend-ram,id=mem0,size=8G",
            "-object", "tdx-guest,id=tdx0",
            "-bios", "/opt/fortanix/enclave-os/OVMF.inteltdx.fd",
            "-kernel", "/opt/fortanix/enclave-os/bzImage",
            "-initrd", "/opt/fortanix/enclave-os/initramfs.gz",
            "-append", "console=ttyS0 rdinit=/init loglevel=7",
            "-device", "vhost-vsock-pci,guest-cid=3",
        ];
        let expected: Vec<String> = expected.into_iter().map(String::from).collect();
        let expected: HashSet<String> = expected.into_iter().collect();
        let platform = TdxPlatform {};
        let args: HashSet<String> = platform.build_qemu_args().into_iter().collect();
        assert_eq!(expected, args, "QEMU args mismatched",);
    }
}
