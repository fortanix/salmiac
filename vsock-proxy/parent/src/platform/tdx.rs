/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::env;

use super::{GuestLaunchResult, GuestTasks};
use crate::platform::qemu::QemuPlatform;

const OVMF_PATH: &str = "/opt/fortanix/enclave-os/OVMF.inteltdx.fd";
const MEMORY_BACKEND_ID: &str = "mem0";
const TDX_ID: &str = "tdx0";
const PCI_HOLE_SIZE_GLOBAL: &str = "q35-pcihost.pci-hole64-size=256G";

struct TdxPlatform;

impl TdxPlatform {
    fn memory_backend(&self) -> String {
        let memory_size = self.memory_size();
        format!(
            "memory-backend-ram,id={},size={}",
            MEMORY_BACKEND_ID, memory_size
        )
    }

    fn tdx_guest() -> String {
        format!("tdx-guest,id={TDX_ID}")
    }
}

impl QemuPlatform for TdxPlatform {
    const GPU_BDF_ENV_VAR_NAME: Option<&str> = Some("TDX_GPU_BDF");

    fn firmware_path(&self) -> Option<&'static str> {
        Some(OVMF_PATH)
    }

    fn host_cc_device_paths(&self) -> Vec<&'static str> {
        vec!["/dev/sgx_enclave", "/dev/sgx_provision", "/dev/sgx_vepc"]
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
        vec![self.memory_backend(), Self::tdx_guest()]
    }

    fn gpu(&self) -> Option<String> {
        env::var("TDX_GPU_BDF").ok()
    }

    fn globals(&self) -> Vec<String> {
        let mut globals = vec![];

        if self.gpu().is_some() {
            globals.push(PCI_HOLE_SIZE_GLOBAL.to_string());
        }
        globals
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
    use super::*;
    use crate::platform::qemu::tests::diff_args;
    use std::iter::FromIterator;

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
        let platform = TdxPlatform {};
        let args: Vec<String> = platform.build_qemu_args().into_iter().collect();
        diff_args(&expected, &Vec::from_iter(args.iter().map(String::as_str)));
    }
}
