/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::collections::HashSet;
use std::env;
use std::path::Path;

use shared::run_subprocess;

pub(super) mod constants {
    pub const CPU_COUNT: &str = "2";
    pub const MEM_SIZE: &str = "8G";
    pub const CPU_COUNT_ENV_VAR: &str = "CPU_COUNT";
    pub const MEM_SIZE_ENV_VAR: &str = "MEM_SIZE";

    pub const KERNEL_PATH: &str = "/opt/fortanix/enclave-os/bzImage";
    pub const KERNEL_CMDLINE: &str = "console=ttyS0 rdinit=/init loglevel=7";
    pub const KVM_DEVICE_PATH: &str = "/dev/kvm";
    pub const VSOCK_HOST_DEVICE_PATH: &str = "/dev/vhost-vsock";
    pub const INITRAMFS_PATH: &str = "/opt/fortanix/enclave-os/initramfs.gz";

    pub const IOMMU_DEVICE_PATH: &str = "/dev/iommu";
    pub const IOMMUFD_ID: &str = "iommufd0";
    pub const IOMMUFD_OBJECT: &str = "iommufd,id=iommufd0";

    // TODO: We need to see how we will assign guest CID when we support multiple
    // containers on single host
    pub const VSOCK_DEVICE: &str = "vhost-vsock-pci,guest-cid=3";
    pub const QEMU_BINARY: &str = "qemu-system-x86_64";
    pub const FW_CFG_MMIO64: &str = "name=opt/ovmf/X-PciMmio64Mb,string=262144";

    pub const ENABLE_GPU_PASSTHROUGH_ENV_VAR: &str = "ENABLE_GPU_PASSTHROUGH";
    pub const DEFAULT_SERIAL_DEVICE: &str = "mon:stdio";
}

pub(super) trait QemuPlatform {
    const GPU_BDF_ENV_VAR_NAME: Option<&str> = None;
    const GPU_BDFS_ENV_VAR_NAME: Option<&str> = None;

    fn firmware_path(&self) -> Option<&'static str>;
    // Device paths related to confidential-computing
    fn host_cc_device_paths(&self) -> Vec<&'static str>;
    fn cpu(&self) -> String;
    fn machine(&self) -> Option<String>;
    fn objects(&self) -> Vec<String>;

    fn gpus(&self) -> Vec<String> {
        let plural = Self::GPU_BDFS_ENV_VAR_NAME.and_then(|name| env::var(name).ok());
        let singular = Self::GPU_BDF_ENV_VAR_NAME.and_then(|name| env::var(name).ok());
        parse_gpu_bdfs(plural.as_deref(), singular.as_deref())
    }

    fn build_gpu_root_port_arg(index: usize) -> String {
        format!("pcie-root-port,id=pci.{},bus=pcie.0", index + 1)
    }

    fn build_vfio_iommu_arg(bdf: &str, index: usize) -> String {
        format!(
            "vfio-pci,host={},bus=pci.{},iommufd={},romfile=",
            bdf,
            index + 1,
            constants::IOMMUFD_ID,
        )
    }

    fn check_files(&self) -> Result<(), String> {
        require_file("Kernel", constants::KERNEL_PATH)?;
        require_file("Initramfs", constants::INITRAMFS_PATH)?;
        require_file("KVM device", constants::KVM_DEVICE_PATH)?;
        require_file("vhost-vsock device", constants::VSOCK_HOST_DEVICE_PATH)?;

        let gpus = self.gpus();
        if !gpus.is_empty() {
            let mut unique_gpus = HashSet::new();
            for gpu in &gpus {
                if !unique_gpus.insert(gpu) {
                    return Err(format!("GPU {gpu} was specified more than once"));
                }
                require_vfio_device(gpu)?;
            }
            require_file("IOMMUFD device", constants::IOMMU_DEVICE_PATH)?;
        } else if Self::GPU_BDFS_ENV_VAR_NAME.is_some() || Self::GPU_BDF_ENV_VAR_NAME.is_some() {
            if env::var(constants::ENABLE_GPU_PASSTHROUGH_ENV_VAR).is_ok_and(|v| v == "true") {
                return Err(format!(
                    "GPU passthrough was enabled at conversion time but {} (or {}) env var is not set.",
                    Self::GPU_BDFS_ENV_VAR_NAME.unwrap_or_default(),
                    Self::GPU_BDF_ENV_VAR_NAME.unwrap_or_default(),
                ));
            }
        }

        if let Some(firmware_path) = self.firmware_path() {
            require_file("Firmware", firmware_path)?;
        }

        for host_dev in self.host_cc_device_paths() {
            require_file("Host device", host_dev)?;
        }

        Ok(())
    }

    fn cpu_count(&self) -> String {
        env_or_default(constants::CPU_COUNT_ENV_VAR, constants::CPU_COUNT)
    }

    fn memory_size(&self) -> String {
        env_or_default(constants::MEM_SIZE_ENV_VAR, constants::MEM_SIZE)
    }

    fn globals(&self) -> Vec<String> {
        vec![]
    }

    fn build_qemu_args(&self) -> Vec<String> {
        let cpu = self.cpu();
        let cpu_count = self.cpu_count();
        let memory_size = self.memory_size();
        let mut args: Vec<&str> = vec![
            "-enable-kvm",
            "-m",
            &memory_size,
            "-smp",
            &cpu_count,
            "-cpu",
            &cpu,
            "-nographic",
            "-monitor",
            "none",
            "-no-reboot",
            "-nodefaults",
            "-serial",
            constants::DEFAULT_SERIAL_DEVICE,
        ];

        if let Some(firmware_path) = self.firmware_path() {
            args.extend(["-bios", firmware_path]);
        }

        let machine = self.machine();
        if let Some(machine) = &machine {
            args.extend(["-machine", machine]);
        }

        let objects = self.objects();
        for object in &objects {
            args.extend(["-object", object]);
        }

        let globals = self.globals();
        for global in &globals {
            args.extend(["-global", global]);
        }

        let gpus = self.gpus();
        let gpu_root_ports = gpus
            .iter()
            .enumerate()
            .map(|(index, _)| Self::build_gpu_root_port_arg(index))
            .collect::<Vec<_>>();
        let gpu_devices = gpus
            .iter()
            .enumerate()
            .map(|(index, bdf)| Self::build_vfio_iommu_arg(bdf, index))
            .collect::<Vec<_>>();
        if !gpus.is_empty() {
            args.extend(["-object", constants::IOMMUFD_OBJECT]);
            for (root_port, gpu_device) in gpu_root_ports.iter().zip(&gpu_devices) {
                args.extend(["-device", root_port, "-device", gpu_device]);
            }
            args.extend(["-fw_cfg", constants::FW_CFG_MMIO64]);
        }

        // Append binary related args for better visibility
        args.extend([
            "-device",
            constants::VSOCK_DEVICE,
            "-kernel",
            constants::KERNEL_PATH,
            "-initrd",
            constants::INITRAMFS_PATH,
            "-append",
            constants::KERNEL_CMDLINE,
        ]);

        args.into_iter()
            .map(|a| String::from(a))
            .collect::<Vec<_>>()
    }

    async fn run(&self) -> Result<(), String> {
        self.check_files()?;
        let args = self.build_qemu_args();
        let args_ref = args.iter().map(|a| a.as_ref()).collect::<Vec<_>>();
        run_subprocess(constants::QEMU_BINARY, &args_ref).await
    }
}

fn parse_gpu_bdfs(plural: Option<&str>, singular: Option<&str>) -> Vec<String> {
    let plural_bdfs = plural
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|bdf| !bdf.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    if !plural_bdfs.is_empty() {
        return plural_bdfs;
    }

    singular
        .map(str::trim)
        .filter(|bdf| !bdf.is_empty())
        .map(str::to_owned)
        .into_iter()
        .collect()
}

#[allow(unused)]
pub fn env_or_default(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn require_file(description: &str, path: &str) -> Result<(), String> {
    if Path::new(path).exists() {
        Ok(())
    } else {
        Err(format!("{description} not found at {path}"))
    }
}

fn require_vfio_device(bdf: &str) -> Result<(), String> {
    let device_path = format!("/sys/bus/pci/devices/{bdf}");
    require_file("GPU PCI device", &device_path)?;

    let driver_path = format!("{device_path}/driver");
    let driver = std::fs::read_link(&driver_path)
        .map_err(|e| format!("failed reading GPU driver at {driver_path}: {e}"))?;

    if driver.file_name().and_then(|name| name.to_str()) != Some("vfio-pci") {
        return Err(format!("GPU {bdf} is not bound to vfio-pci"));
    }

    require_file("VFIO control device", "/dev/vfio/vfio")?;

    let iommu_group_path = format!("{device_path}/iommu_group");
    let iommu_group = std::fs::read_link(&iommu_group_path)
        .map_err(|e| format!("failed reading IOMMU group for GPU {bdf}: {e}"))?;

    let group = iommu_group
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid IOMMU group path for GPU {bdf}"))?;

    let vfio_group_path = format!("/dev/vfio/{group}");
    require_file("VFIO group device", &vfio_group_path)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::parse_gpu_bdfs;
    use std::assert_eq;
use std::collections::HashMap;
    use std::collections::HashSet;

    #[test]
    fn plural_gpu_bdfs_take_precedence() {
        assert_eq!(
            parse_gpu_bdfs(Some("0000:21:00.0, 0000:81:00.0"), Some("0000:01:00.0")),
            vec!["0000:21:00.0", "0000:81:00.0"],
        );
    }

    #[test]
    fn plural_gpu_bdfs_single_gpu() {
        assert_eq!(
            parse_gpu_bdfs(Some("0000:21:00.0"), None),
            vec!["0000:21:00.0"],
        )
    }

    #[test]
    fn empty_plural_gpu_bdfs_fall_back_to_singular() {
        assert_eq!(
            parse_gpu_bdfs(Some(" , "), Some(" 0000:21:00.0 ")),
            vec!["0000:21:00.0"],
        );
    }

    #[test]
    fn empty_gpu_bdf_variables_produce_no_devices() {
        assert!(parse_gpu_bdfs(Some(""), Some(" ")).is_empty());
    }

    fn parse_args_as_kvp<'a>(args: &[&'a str]) -> HashMap<&'a str, Option<&'a str>> {
        let mut map = HashMap::<&str, Option<&str>>::new();

        let mut last_arg = None;

        for arg in args {
            if arg.starts_with("-") {
                last_arg = Some(arg);
                map.insert(arg, None);
            } else {
                if let Some(key) = last_arg {
                    map.entry(key).and_modify(|val| *val = Some(arg));
                    last_arg = None;
                } else {
                    panic!();
                }
            }
        }
        map
    }

    pub fn diff_args(expected: &[&str], actual: &[&str]) {
        let expected = parse_args_as_kvp(expected);
        let actual = parse_args_as_kvp(actual);

        let keys_in_expected = expected.keys().copied().collect::<HashSet<_>>();
        let keys_in_actual = actual.keys().copied().collect::<HashSet<_>>();
        let intersect = keys_in_expected
            .intersection(&keys_in_actual)
            .copied()
            .collect::<HashSet<_>>();

        let mut success = true;

        for key in &intersect {
            if !expected.get(key).unwrap().eq(actual.get(key).unwrap()) {
                println!(
                    "Argument {:?} differs between expected and actual: {:?} vs {:?}",
                    key,
                    expected.get(key).unwrap(),
                    actual.get(key).unwrap()
                );
                success = false;
            }
        }

        for item in keys_in_expected.difference(&intersect) {
            println!("Present in actual but not in expected: {:?}", item);
            success = false;
        }

        for item in keys_in_actual.difference(&intersect) {
            println!("Present in expected but not in actual: {:?}", item);
            success = false;
        }

        assert!(success);
    }
}
