/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::env;

use super::{GuestLaunchResult, GuestTasks};
use crate::platform::qemu::{env_or_default, QemuPlatform};

const OVMF_PATH: &str = "/opt/fortanix/enclave-os/OVMF.amdsev.fd";

/// - Use host passthrough, see https://www.qemu.org/docs/master/system/i386/cpu.html
/// - Unset TSA_L1_NO and TSA_SQ_NO:
///   See: https://www.amd.com/content/dam/amd/en/documents/resources/bulletin/technical-guidance-for-mitigating-transient-scheduler-attacks.pdf
///   "the SEV-SNP FW will not allow the hypervisor to set the TSA_L1_NO or TSA_SQ_NO CPUID bits"
/// - TODO(before merge): Confirm family=0,model=0,stepping=0
const DEFAULT_CPU: &str = "EPYC-v4,-tsa-sq-no,-tsa-l1-no,family=0,model=0,stepping=0";

// https://docs.amd.com/v/u/en-US/58207-using-sev-with-amd-epyc-processors
//
// "Since SNP is only supported from processor series 7003 and newer, the c-bit (cbitpos) will always be 51"
const DEFAULT_CBITPOS: &str = "51";
const DEFAULT_REDUCED_PHYS_BITS: &str = "1";

// We want SMT disabled
const DEFAULT_POLICY: &str = "0x20000";

const SNP_GUEST_ID: &str = "sev0";
const MEMORY_BACKEND_ID: &str = "ram1";

struct SnpPlatform;

impl SnpPlatform {
    fn memory_backend(&self) -> String {
        let memory_size = self.memory_size();
        let memory_backend = format!(
            "memory-backend-memfd,id={MEMORY_BACKEND_ID},size={memory_size},share=true,prealloc=false",
        );
        memory_backend
    }

    fn snp_guest() -> String {
        let cbitpos = env_or_default("SNP_CBITPOS", DEFAULT_CBITPOS);
        let reduced_phys_bits = env_or_default("SNP_REDUCED_PHYS_BITS", DEFAULT_REDUCED_PHYS_BITS);
        let policy = env_or_default("SNP_POLICY", DEFAULT_POLICY);
        let snp_guest = format!(
            "sev-snp-guest,id={SNP_GUEST_ID},cbitpos={cbitpos},reduced-phys-bits={reduced_phys_bits},kernel-hashes=on,policy={policy}"
        );
        snp_guest
    }
}

impl QemuPlatform for SnpPlatform {
    fn firmware_path(&self) -> Option<&'static str> {
        Some(OVMF_PATH)
    }

    fn host_device_paths(&self) -> Vec<&'static str> {
        vec!["/dev/sev"]
    }

    fn cpu(&self) -> String {
        env_or_default("SNP_CPU", DEFAULT_CPU)
    }

    fn machine(&self) -> Option<String> {
        let machine = format!(
            "q35,confidential-guest-support={SNP_GUEST_ID},vmport=off,memory-backend={MEMORY_BACKEND_ID}"
        );
        Some(machine)
    }

    fn objects(&self) -> Vec<String> {
        vec![self.memory_backend(), Self::snp_guest()]
    }

    fn gpu(&self) -> Option<String> {
        env::var("SNP_GPU_BDF").ok()
    }
}

pub(crate) fn should_forward_client_logs() -> bool {
    true
}

pub(crate) fn launch_guest() -> GuestLaunchResult {
    let enclave_process = tokio::spawn(start_snp_guest());

    GuestLaunchResult { enclave_process }
}

pub(crate) fn start_post_connect_guest_tasks() -> GuestTasks {
    GuestTasks::new()
}

async fn start_snp_guest() -> Result<(), String> {
    SnpPlatform.run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_build_qemu_snp_args() {
        // Captured before the QemuPlatform refactoring, with modifications to the memory size.
        // Ignore formatting to keep logical key/value pairs align better in a single line.
        #[rustfmt::skip]
        let expected = vec![
            "-enable-kvm", "-nographic", "-monitor", "none", "-no-reboot",
            "-machine", "q35,confidential-guest-support=sev0,vmport=off,memory-backend=ram1",
            "-cpu", "EPYC-v4,-tsa-sq-no,-tsa-l1-no,family=0,model=0,stepping=0", "-smp", "2", "-m", "8G",
            "-object", "memory-backend-memfd,id=ram1,size=8G,share=true,prealloc=false",
            "-object", "sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,policy=0x20000",
            "-bios", "/opt/fortanix/enclave-os/OVMF.amdsev.fd",
            "-kernel", "/opt/fortanix/enclave-os/bzImage",
            "-initrd", "/opt/fortanix/enclave-os/initramfs.gz",
            "-append", "console=ttyS0 rdinit=/init loglevel=7",
            "-device", "vhost-vsock-pci,guest-cid=3",
        ];
        let expected: Vec<String> = expected.into_iter().map(String::from).collect();
        let expected: HashSet<String> = expected.into_iter().collect();
        let platform = SnpPlatform {};
        let args: HashSet<String> = platform.build_qemu_args().into_iter().collect();
        assert_eq!(expected, args, "QEMU args mismatch",);
    }
}
