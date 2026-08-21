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

    // TODO: We need to see how we will assign guest CID when we support multiple
    // containers on single host
    pub const VSOCK_DEVICE: &str = "vhost-vsock-pci,guest-cid=3";
    pub const QEMU_BINARY: &str = "qemu-system-x86_64";
    pub const ENABLE_GPU_PASSTHROUGH_ENV_VAR: &str = "ENABLE_GPU_PASSTHROUGH";
    pub const DEFAULT_SERIAL_DEVICE: &str = "mon:stdio";
}

pub(super) trait QemuPlatform {
    const GPU_BDF_ENV_VAR_NAME: Option<&'static str> = None;
    const GPU_BDFS_ENV_VAR_NAME: Option<&'static str> = None;

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

    fn build_vfio_iommu_arg(bdf: &str, index: usize) -> String {
        format!(
            "vfio-pci,host={},bus=pci.{},iommufd={},romfile=",
            bdf,
            index + 1,
            iommu::IOMMUFD_ID,
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
                iommu::require_vfio_device(gpu)?;
            }
            require_file("IOMMUFD device", iommu::DEVICE_PATH)?;
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

    fn build_qemu_gpu_args(&self) -> Result<Option<Vec<String>>, String> {
        let gpus = self.gpus();
        if gpus.is_empty() {
            return Ok(None);
        }

        let mut args = Vec::new();
        let gpu_root_ports = gpus
            .iter()
            .enumerate()
            .map(|(index, _)| build_gpu_root_port_arg(index))
            .collect::<Vec<_>>();
        let gpu_devices = gpus
            .iter()
            .enumerate()
            .map(|(index, bdf)| Self::build_vfio_iommu_arg(bdf, index))
            .collect::<Vec<_>>();
        let fw_cfg_mmio64 = {
            let size_mb = iommu::pci_mmio64_mb(&gpus)?;
            format!("name=opt/ovmf/X-PciMmio64Mb,string={size_mb}")
        };

        args.extend(["-object".to_owned(), iommu::IOMMUFD_OBJECT.to_owned()]);
        for (root_port, gpu_device) in gpu_root_ports.into_iter().zip(gpu_devices) {
            args.extend([
                "-device".to_owned(),
                root_port,
                "-device".to_owned(),
                gpu_device,
            ]);
        }
        args.extend(["-fw_cfg".to_owned(), fw_cfg_mmio64]);
        Ok(Some(args))
    }

    fn build_qemu_args(&self) -> Result<Vec<String>, String> {
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

        let gpu_args = self.build_qemu_gpu_args()?;
        if let Some(gpu_args) = &gpu_args {
            args.extend(gpu_args.iter().map(String::as_str));
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

        Ok(args
            .into_iter()
            .map(|a| String::from(a))
            .collect::<Vec<_>>())
    }

    async fn run(&self) -> Result<(), String> {
        self.check_files()?;
        let args = self.build_qemu_args()?;
        let args_ref = args.iter().map(|a| a.as_ref()).collect::<Vec<_>>();
        run_subprocess(constants::QEMU_BINARY, &args_ref).await
    }
}

mod iommu {
    use std::fs;

    use log::{info, warn};

    use super::require_file;

    pub(super) const DEVICE_PATH: &str = "/dev/iommu";
    pub(super) const IOMMUFD_ID: &str = "iommufd0";
    pub(super) const IOMMUFD_OBJECT: &str = "iommufd,id=iommufd0";

    const MIB: u64 = 1024 * 1024;
    const MIN_PCI_MMIO64_MB: u64 = 256 * 1024;
    const OTHER_DEVICES_HEADROOM_MB: u64 = 64 * 1024;
    const FALLBACK_GPU_BAR_MB: u64 = 128 * 1024;
    const MAX_PCI_MMIO64_MB: u64 = 8 * 1024 * 1024;

    // Parses given gpus' resource file(s) provided by sysfs
    // to calculate amount of total memory that are going to be
    // passed-through qemu instance.
    // The structure of 'resource' file could be found at:
    // https://github.com/torvalds/linux/blob/master/Documentation/PCI/sysfs-pci.rst
    pub(super) fn pci_mmio64_mb(gpus: &[String]) -> Result<u64, String> {
        let mut bar_total = 0_u64;
        let mut all_resources_read = true;
        for bdf in gpus {
            let resource_path = format!("/sys/bus/pci/devices/{bdf}/resource");
            match fs::read_to_string(&resource_path) {
                Ok(resources) => {
                    bar_total = bar_total
                        .checked_add(parse_gpu_bar_total(&resources)?)
                        .ok_or_else(|| "GPU BAR size total overflowed u64".to_string())?;
                }
                Err(error) => {
                    all_resources_read = false;
                    warn!(
                        "Unable to read GPU BAR resources from {}: {}. Using conservative fallback sizing.",
                        resource_path, error
                    );
                }
            }
        }

        let size_mb = pci_mmio64_mb_from_bar_total(
            if all_resources_read { bar_total } else { 0 },
            gpus.len(),
        )?;
        info!(
            "Configured PCI MMIO64 window at {} MiB for {} GPU(s) with {} MiB of BAR resources",
            size_mb,
            gpus.len(),
            bar_total / MIB,
        );
        Ok(size_mb)
    }

    // Calculates BAR size per gpu.
    // Parses 'resource' files, a resource file may contain more than one resource.
    // For example, consider following resource file content with two entries
    // 0x0000215000000000 0x0000215000ffffff 0x000000000014220c
    // 0x0000200000000000 0x0000201fffffffff 0x000000000014220c
    // Each line represents certain memory bank of the device.
    // The format is: <start physical address> <end physical address> <flags>
    fn parse_gpu_bar_total(resources: &str) -> Result<u64, String> {
        resources.lines().take(6).try_fold(0_u64, |total, line| {
            let mut fields = line.split_whitespace();
            let start = parse_pci_resource_value(fields.next(), line)?;
            let end = parse_pci_resource_value(fields.next(), line)?;
            let size = if end > start {
                end.checked_sub(start)
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| format!("PCI BAR size overflow in resource line {line:?}"))?
            } else {
                0
            };
            total
                .checked_add(size)
                .ok_or_else(|| "GPU BAR size total overflowed u64".to_string())
        })
    }

    fn parse_pci_resource_value(value: Option<&str>, line: &str) -> Result<u64, String> {
        let value = value.ok_or_else(|| format!("Malformed PCI resource line {line:?}"))?;
        u64::from_str_radix(value.trim_start_matches("0x"), 16)
            .map_err(|error| format!("Invalid PCI resource value {value:?}: {error}"))
    }

    fn pci_mmio64_mb_from_bar_total(bar_total: u64, gpu_count: usize) -> Result<u64, String> {
        let need_mb = if bar_total > 0 {
            let bar_mb = bar_total / MIB;
            bar_mb
                .checked_add(bar_mb / 4)
                .and_then(|value| value.checked_add(OTHER_DEVICES_HEADROOM_MB))
                .ok_or_else(|| "PCI MMIO64 size calculation overflowed u64".to_string())?
        } else {
            MIN_PCI_MMIO64_MB
                .checked_add(
                    FALLBACK_GPU_BAR_MB
                        .checked_mul(gpu_count as u64)
                        .ok_or_else(|| {
                            "PCI MMIO64 fallback calculation overflowed u64".to_string()
                        })?,
                )
                .ok_or_else(|| "PCI MMIO64 fallback calculation overflowed u64".to_string())?
        };

        let mut size_mb = MIN_PCI_MMIO64_MB;
        while size_mb < need_mb {
            size_mb = size_mb
                .checked_mul(2)
                .ok_or_else(|| "PCI MMIO64 power-of-two rounding overflowed u64".to_string())?;
        }
        validate_pci_mmio64_mb(size_mb)?;
        Ok(size_mb)
    }

    fn validate_pci_mmio64_mb(size_mb: u64) -> Result<(), String> {
        if size_mb < MIN_PCI_MMIO64_MB {
            return Err(format!(
                "Computed PCI MMIO64 window {size_mb} MiB is below the {MIN_PCI_MMIO64_MB} MiB minimum"
            ));
        }
        if size_mb > MAX_PCI_MMIO64_MB {
            return Err(format!(
                "Computed PCI MMIO64 window {size_mb} MiB exceeds the {} MiB limit",
                MAX_PCI_MMIO64_MB
            ));
        }
        if !size_mb.is_power_of_two() {
            return Err(format!(
                "Computed PCI MMIO64 window {size_mb} MiB is not a power of two"
            ));
        }
        Ok(())
    }

    pub(super) fn require_vfio_device(bdf: &str) -> Result<(), String> {
        let device_path = format!("/sys/bus/pci/devices/{bdf}");
        require_file("GPU PCI device", &device_path)?;

        let driver_path = format!("{device_path}/driver");
        let driver = fs::read_link(&driver_path)
            .map_err(|e| format!("failed reading GPU driver at {driver_path}: {e}"))?;

        if driver.file_name().and_then(|name| name.to_str()) != Some("vfio-pci") {
            return Err(format!("GPU {bdf} is not bound to vfio-pci"));
        }

        require_file("VFIO control device", "/dev/vfio/vfio")?;

        let iommu_group_path = format!("{device_path}/iommu_group");
        let iommu_group = fs::read_link(&iommu_group_path)
            .map_err(|e| format!("failed reading IOMMU group for GPU {bdf}: {e}"))?;

        let group = iommu_group
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("invalid IOMMU group path for GPU {bdf}"))?;

        let vfio_group_path = format!("/dev/vfio/{group}");
        require_file("VFIO group device", &vfio_group_path)
    }

    #[cfg(test)]
    mod tests {
        use super::{parse_gpu_bar_total, pci_mmio64_mb_from_bar_total, MIB};

        #[test]
        fn parses_and_sums_gpu_bars() {
            let resources = concat!(
                "0x1000 0x1fff 0x0\n",
                "0x2000 0x3fff 0x0\n",
                "0x0 0x0 0x0\n",
                "0x4000 0x7fff 0x0\n",
                "0x0 0x0 0x0\n",
                "0x0 0x0 0x0\n",
                "0x8000 0xffff 0x0\n",
            );
            assert_eq!(parse_gpu_bar_total(resources).unwrap(), 0x7000);
        }

        #[test]
        fn sizes_mmio_window_from_bar_total() {
            assert_eq!(
                pci_mmio64_mb_from_bar_total(128 * 1024 * MIB, 1).unwrap(),
                256 * 1024
            );
            assert_eq!(
                pci_mmio64_mb_from_bar_total(256 * 1024 * MIB, 2).unwrap(),
                512 * 1024
            );
        }

        #[test]
        fn falls_back_when_bar_resources_are_unavailable() {
            assert_eq!(pci_mmio64_mb_from_bar_total(0, 1).unwrap(), 512 * 1024);
        }
    }
}

fn build_gpu_root_port_arg(index: usize) -> String {
    let number = index + 1;
    format!(
        "pcie-root-port,id=pci.{number},bus=pcie.0,addr=0x{:x},chassis={number},slot={number}",
        number + 1,
    )
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

#[cfg(test)]
pub(crate) mod tests {
    use super::{build_gpu_root_port_arg, parse_gpu_bdfs};
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

    #[test]
    fn gpu_root_ports_have_unique_topology() {
        assert_eq!(
            build_gpu_root_port_arg(0),
            "pcie-root-port,id=pci.1,bus=pcie.0,addr=0x2,chassis=1,slot=1"
        );
        assert_eq!(
            build_gpu_root_port_arg(1),
            "pcie-root-port,id=pci.2,bus=pcie.0,addr=0x3,chassis=2,slot=2"
        );
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
