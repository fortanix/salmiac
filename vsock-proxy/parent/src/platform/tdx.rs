/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::env;

use super::{GuestLaunchResult, GuestTasks};
use crate::platform::qemu::QemuPlatform;

const OVMF_PATH: &str = "/opt/fortanix/enclave-os/OVMF.tdx.fd";
const GUEST_DEV_PATH: &str = "/dev/tdx_guest";
const MEMORY_BACKEND_ID: &str = "mem0";
const MEMORY_SIZE: &str = "8G";
const TDX_ID: &str = "tdx";

struct TdxPlatform;

impl TdxPlatform {
    fn memory_backend() -> String {
        format!("memory-backend-ram,id={MEMORY_BACKEND_ID},size={MEMORY_SIZE}")
    }

    fn tdx_guest() -> String {
        // At the moment the host does not run quote-generation service.
        // With quote-generation service enablement, we can either connect to it via vsock or socket file
        // See https://github.com/intel/confidential-computing.tee.dcap/blob/3aa24f6df004f092556aef10e0ab422cb0395e38/QuoteGeneration/quote_wrapper/qgs/test_client.c#L21
        // Example of passing vsock information for quote-generation daemon: '"quote-generation-socket":{{"type":"vsock","cid":"2","port":"4050"}}'
        format!(r#"{{"qom-type":"tdx-guest","id":"{}"}}"#, TDX_ID)
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

    fn memory_size(&self) -> &'static str {
        MEMORY_SIZE
    }

    fn machine(&self) -> Option<String> {
        let machine = format!(
            "q35,kernel_irqchip=split,confidential-guest-support={},memory-backend={}",
            TDX_ID, MEMORY_BACKEND_ID
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
    fn test_build_qemu_snp_args() {
        let expected = vec![
            "-enable-kvm",
            "-nographic",
            "-monitor",
            "none",
            "-no-reboot",
            "-machine",
            "q35,kernel_irqchip=split,confidential-guest-support=tdx,memory-backend=mem0",
            "-cpu",
            "host",
            "-smp",
            "2",
            "-m",
            "8G",
            "-object",
            "memory-backend-ram,id=mem0,size=8G",
            "-object",
            r#"{"qom-type":"tdx-guest","id":"tdx"}"#,
            "-bios",
            "/opt/fortanix/enclave-os/OVMF.tdx.fd",
            "-kernel",
            "/opt/fortanix/enclave-os/bzImage",
            "-initrd",
            "/opt/fortanix/enclave-os/initramfs.gz",
            "-append",
            "console=ttyS0 rdinit=/init loglevel=7",
            "-device",
            "vhost-vsock-pci,guest-cid=3",
        ];
        let expected: Vec<String> = expected.into_iter().map(String::from).collect();
        let expected: HashSet<String> = expected.into_iter().collect();
        let platform = TdxPlatform {};
        let args: HashSet<String> = platform.build_qemu_args().into_iter().collect();
        println!("Expected has additional: {:?}", expected.difference(&args));
        println!("Args has additional: {:?}", args.difference(&expected));
        assert_eq!(expected, args, "QEMU args mismatched",);
    }
}
