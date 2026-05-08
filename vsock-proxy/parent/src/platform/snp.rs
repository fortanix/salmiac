use std::env;
use std::path::Path;

use shared::run_subprocess;

use super::{GuestLaunchResult, GuestTasks};

const QEMU_BINARY: &str = "qemu-system-x86_64";

const OVMF_PATH: &str = "/opt/fortanix/enclave-os/OVMF.amdsev.fd";

const CPU_COUNT: &str = "2";
const MEMORY_SIZE: &str = "8192M";

/// - Use host passthrough, see https://www.qemu.org/docs/master/system/i386/cpu.html
/// - Unset TSA_L1_NO and TSA_SQ_NO:
///   See: https://www.amd.com/content/dam/amd/en/documents/resources/bulletin/technical-guidance-for-mitigating-transient-scheduler-attacks.pdf
///   "the SEV-SNP FW will not allow the hypervisor to set the TSA_L1_NO or TSA_SQ_NO CPUID bits"
/// - TODO(before merge): Confirm family=0,model=0,stepping=0
const DEFAULT_CPU: &str = "host,-tsa-sq-no,-tsa-l1-no,family=0,model=0,stepping=0";

// https://docs.amd.com/v/u/en-US/58207-using-sev-with-amd-epyc-processors
//
// "Since SNP is only supported from processor series 7003 and newer, the c-bit (cbitpos) will always be 51"
const DEFAULT_CBITPOS: &str = "51";
const DEFAULT_REDUCED_PHYS_BITS: &str = "1";

// We want SMT disabled
const DEFAULT_POLICY: &str = "0x20000";

// TODO(before merge): Make UKI instead, and need to check on final kernel cmdline
const KERNEL_CMDLINE: &str = "console=ttyS0 rdinit=/init loglevel=7";
const KERNEL_PATH: &str = "/opt/fortanix/enclave-os/kernel";
const INITRAMFS_PATH: &str = "/opt/fortanix/enclave-os/initramfs.cpio.gz";

const SNP_GUEST_ID: &str = "sev0";
const MEMORY_BACKEND_ID: &str = "ram1";

// TODO(before merge): need to  currently like this for debugging
const SERIAL: &str = "telnet:0.0.0.0:4321,server,wait";

// TODO: We need to see how we will assign guest CID when we support multiple
// containers on single host
const VSOCK_DEVICE: &str = "vhost-vsock-pci,guest-cid=3";

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
    require_file("SNP kernel", KERNEL_PATH)?;
    require_file("SNP initramfs", INITRAMFS_PATH)?;
    require_file("SNP OVMF firmware", OVMF_PATH)?;
    require_file("KVM device", "/dev/kvm")?;
    require_file("SEV device", "/dev/sev")?;

    let cpu = env_or_default("SNP_CPU", DEFAULT_CPU);
    let cbitpos = env_or_default("SNP_CBITPOS", DEFAULT_CBITPOS);
    let reduced_phys_bits = env_or_default("SNP_REDUCED_PHYS_BITS", DEFAULT_REDUCED_PHYS_BITS);
    let policy = env_or_default("SNP_POLICY", DEFAULT_POLICY);

    let machine = format!(
        "q35,confidential-guest-support={SNP_GUEST_ID},vmport=off,memory-backend={MEMORY_BACKEND_ID}"
    );

    let memory_backend = format!(
        "memory-backend-memfd,id={MEMORY_BACKEND_ID},size={MEMORY_SIZE},share=true,prealloc=false"
    );

    let snp_guest = format!(
        "sev-snp-guest,id={SNP_GUEST_ID},cbitpos={cbitpos},reduced-phys-bits={reduced_phys_bits},kernel-hashes=on,policy={policy}"
    );

    let args = [
        "-enable-kvm",
        "-display",
        "none",
        "-serial",
        SERIAL,
        "-monitor",
        "none",
        "-no-reboot",
        "-machine",
        &machine,
        "-cpu",
        &cpu,
        "-smp",
        CPU_COUNT,
        "-m",
        MEMORY_SIZE,
        "-object",
        &memory_backend,
        "-object",
        &snp_guest,
        "-bios",
        OVMF_PATH,
        "-kernel",
        KERNEL_PATH,
        "-initrd",
        INITRAMFS_PATH,
        "-append",
        KERNEL_CMDLINE,
        "-device",
        VSOCK_DEVICE,
    ];

    run_subprocess(QEMU_BINARY, &args).await
}

fn env_or_default(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn require_file(description: &str, path: &str) -> Result<(), String> {
    if Path::new(path).exists() {
        Ok(())
    } else {
        Err(format!("{description} not found at {path}"))
    }
}
