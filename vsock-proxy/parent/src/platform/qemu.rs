/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::ErrorKind;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use log::debug;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use shared::{run_subprocess, VSOCK_LISTENER_CID};
use tokio_vsock::VsockListener;

use crate::platform::GuestLaunchResult;
use crate::utils::qemu as qemu_utils;

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

    pub const CID_START: u16 = 1024;
    pub const QEMU_BINARY: &str = "qemu-system-x86_64";
    pub const ENABLE_GPU_PASSTHROUGH_ENV_VAR: &str = "ENABLE_GPU_PASSTHROUGH";
    pub const GPU_COUNT_ENV_VAR: &str = "GPU_COUNT";
    pub const DEFAULT_SERIAL_DEVICE: &str = "mon:stdio";

    pub const VHOST_VIRTIO: u8 = 0xAF;
}

nix::ioctl_write_ptr!(set_guest_cid, constants::VHOST_VIRTIO, 0x60, u64);

pub struct VmConnectionConfig {
    pub(crate) parent_vsock_listener: tokio_vsock::VsockListener,
    pub(crate) guest_vsock_cid: u64,
}

pub struct GPUSettings {
    pub bdfs: Vec<String>,
    pub mmio64_mb: u64,
    pub iommufd: File,
    pub vfio_fds: Vec<File>,
}

impl GPUSettings {
    pub fn try_new_from_env_variable(
        env_var: Option<&'static str>,
    ) -> Result<Option<Self>, String> {
        let gpu_bdfs_value = env_var.and_then(|name| env::var(name).ok());
        let gpu_count_value = env::var(constants::GPU_COUNT_ENV_VAR).ok();
        if gpu_bdfs_value.is_some() && gpu_count_value.is_some() {
            return Err(format!(
                "{:?} and {} are mutually exclusive",
                env_var,
                constants::GPU_COUNT_ENV_VAR
            ));
        }

        if let Some(gpu_bdfs_value) = gpu_bdfs_value {
            let gpu_settings = Self::try_new_from_bdfs(gpu_bdfs_value)?;
            return Ok(Some(gpu_settings));
        }

        if let Some(gpu_count_value) = gpu_count_value {
            let gpu_settings = Self::try_new_from_gpu_count(gpu_count_value)?;
            return Ok(Some(gpu_settings));
        }

        Ok(None)
    }

    fn try_new_from_bdfs(bdfs_value: String) -> Result<Self, String> {
        let bdfs = parse_gpu_bdfs(&bdfs_value);
        if bdfs.is_empty() {
            return Err(format!("Unable to parse bdfs from {bdfs_value}"));
        }

        Self::validate_bdfs(&bdfs)?;
        let mmio64_mb = qemu_utils::pci_mmio64_mb(&bdfs)?;
        let iommufd = qemu_utils::open_iommufd()?;
        let vfio_fds = bdfs
            .iter()
            .map(|bdf| qemu_utils::open_vfio_device(bdf))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(GPUSettings {
            bdfs,
            mmio64_mb,
            iommufd,
            vfio_fds,
        });
    }

    fn try_new_from_gpu_count(gpu_count_value: String) -> Result<Self, String> {
        let gpu_count = parse_gpu_count(gpu_count_value)?;
        let gpu_count = match gpu_count {
            GPUCount::All => None,
            GPUCount::Count(count) => Some(count),
        };
        let vfio_devices = qemu_utils::enumerate_vfio_gpu_devices(gpu_count)?;
        let mmio64_mb = qemu_utils::pci_mmio64_mb_from_vfio_devices(&vfio_devices)?;
        let iommufd = qemu_utils::open_iommufd()?;
        let bdfs = vfio_devices
            .iter()
            .map(|device| device.bdf.clone())
            .collect();
        let vfio_fds = vfio_devices.into_iter().map(|device| device.file).collect();

        Ok(GPUSettings {
            bdfs,
            mmio64_mb,
            iommufd,
            vfio_fds,
        })
    }

    fn validate_bdfs(bdfs: &[String]) -> Result<(), String> {
        // Validate passed bdf devices
        // Duplicates are not allowed
        let mut unique_gpus = HashSet::new();
        for bdf in bdfs {
            if !unique_gpus.insert(bdf) {
                return Err(format!("GPU {bdf} was specified more than once"));
            }
        }
        Ok(())
    }

    pub fn build_qemu_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        args.extend([
            "-object".to_owned(),
            qemu_utils::build_iommufd_object(self.iommufd.as_raw_fd()),
        ]);
        for (index, (bdf, vfio_fd)) in self.bdfs.iter().zip(&self.vfio_fds).enumerate() {
            debug!(
                "Passing GPU {} to QEMU using VFIO fd {}",
                bdf,
                vfio_fd.as_raw_fd()
            );
            let root_port = qemu_utils::build_pcie_root_port(index);
            let device = qemu_utils::build_vfio_iommu_arg(vfio_fd.as_raw_fd(), index);
            args.extend([
                "-device".to_owned(),
                root_port,
                "-device".to_owned(),
                device,
            ]);
        }
        let fw_cfg_mmio64 = format!("name=opt/ovmf/X-PciMmio64Mb,string={}", self.mmio64_mb);

        args.extend(["-fw_cfg".to_owned(), fw_cfg_mmio64]);
        args
    }
}

pub(super) trait QemuPlatform {
    const GPU_BDFS_ENV_VAR_NAME: Option<&'static str> = None;

    fn firmware_path(&self) -> Option<&'static str>;
    // Device paths related to confidential-computing
    fn host_cc_device_paths(&self) -> Vec<&'static str>;
    fn cpu(&self) -> String;
    fn machine(&self) -> Option<String>;
    fn objects(&self) -> Vec<String>;

    fn gpu_settings(&self) -> Result<Option<GPUSettings>, String> {
        let gpu_settings = GPUSettings::try_new_from_env_variable(Self::GPU_BDFS_ENV_VAR_NAME)?;
        if gpu_settings.is_none() {
            let supports_gpu_passthrough = Self::GPU_BDFS_ENV_VAR_NAME.is_some();
            let gpu_passthrough_enabled = env::var(constants::ENABLE_GPU_PASSTHROUGH_ENV_VAR)
                .is_ok_and(|value| value == "true");
            if supports_gpu_passthrough && gpu_passthrough_enabled {
                return Err(format!(
                    "GPU passthrough was enabled at conversion time but neither {} nor {} is set.",
                    Self::GPU_BDFS_ENV_VAR_NAME.unwrap_or_default(),
                    constants::GPU_COUNT_ENV_VAR,
                ));
            }
        }

        Ok(gpu_settings)
    }

    fn check_files(&self) -> Result<(), String> {
        qemu_utils::require_file("Kernel", constants::KERNEL_PATH)?;
        qemu_utils::require_file("Initramfs", constants::INITRAMFS_PATH)?;
        qemu_utils::require_file("KVM device", constants::KVM_DEVICE_PATH)?;
        qemu_utils::require_file("vhost-vsock device", constants::VSOCK_HOST_DEVICE_PATH)?;

        if let Some(firmware_path) = self.firmware_path() {
            qemu_utils::require_file("Firmware", firmware_path)?;
        }

        for host_dev in self.host_cc_device_paths() {
            qemu_utils::require_file("Host device", host_dev)?;
        }

        Ok(())
    }

    fn cpu_count(&self) -> String {
        env_or_default(constants::CPU_COUNT_ENV_VAR, constants::CPU_COUNT)
    }

    fn memory_size(&self) -> String {
        env_or_default(constants::MEM_SIZE_ENV_VAR, constants::MEM_SIZE)
    }

    fn globals(&self, _gpu_settings: Option<&GPUSettings>) -> Result<Vec<String>, String> {
        Ok(vec![])
    }

    fn build_qemu_args(
        &self,
        gpu_settings: Option<&GPUSettings>,
        vsock_fd: RawFd,
        vsock_cid: u64,
    ) -> Result<Vec<String>, String> {
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

        let globals = self.globals(gpu_settings)?;
        for global in &globals {
            args.extend(["-global", global]);
        }

        let gpu_args = gpu_settings.map(|g| g.build_qemu_args());
        if let Some(gpu_args) = &gpu_args {
            args.extend(gpu_args.iter().map(String::as_str));
        }

        let vsock_device_str = format!(
            "vhost-vsock-pci,id=vhost-vsock-pci0,vhostfd={},guest-cid={}",
            vsock_fd, vsock_cid
        );

        args.extend(["-device", vsock_device_str.as_str()]);

        // Append binary related args for better visibility
        args.extend([
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

    fn launch_guest(&self) -> Result<GuestLaunchResult, String> {
        self.check_files()?;

        let gpu_settings = self.gpu_settings()?;
        let (enclave_connection_config, vsock_fd) = probe_vm_connection_config()?;
        let args = self.build_qemu_args(
            gpu_settings.as_ref(),
            vsock_fd.as_raw_fd(),
            enclave_connection_config.guest_vsock_cid,
        )?;

        let enclave_process = tokio::spawn(async move {
            let args_ref = args.iter().map(|a| a.as_ref()).collect::<Vec<_>>();
            // Move ownership here so it won't get dropped
            let _vsock_fd = vsock_fd;
            run_subprocess(constants::QEMU_BINARY, &args_ref).await
        });

        Ok(GuestLaunchResult {
            enclave_process,
            enclave_connection_config,
        })
    }
}

fn parse_gpu_bdfs(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|bdf| !bdf.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Based on Fortanix VME runner implementation (amdsevsnp.rs: get_available_guest_cid_with_fd)
fn probe_vm_connection_config() -> Result<(VmConnectionConfig, OwnedFd), String> {
    use rand::Rng;

    let random_start = rand::thread_rng().gen_range(constants::CID_START..u16::MAX);
    for cid in (random_start..u16::MAX).chain(constants::CID_START..random_start) {
        // Try to check if the socket address is already bound
        let parent_socket = match VsockListener::bind(VSOCK_LISTENER_CID, cid.into()) {
            Err(e) => match e.kind() {
                ErrorKind::AddrInUse => Ok(None),
                _ => Err(format!("unable to bind to vsock port: {e}")),
            },
            Ok(s) => Ok(Some(s)),
        }?;

        let parent_socket = if let Some(s) = parent_socket {
            s
        } else {
            continue;
        };

        // set_guest_cid expects u64 due to underlying ioctl call.
        let cid = cid as u64;
        // We're deliberately omitting O_CLOEXEC here as we want
        // the child process inherit the opened file descriptors.
        let fd = nix::fcntl::open(
            constants::VSOCK_HOST_DEVICE_PATH,
            OFlag::O_RDWR,
            Mode::empty(),
        )
        .map_err(|e| format!("unable to open vhost-vsock device: {}", e))?;

        let res = unsafe { set_guest_cid(fd.as_raw_fd(), &cid) };
        match res {
            Ok(_) => {
                return Ok((
                    VmConnectionConfig {
                        parent_vsock_listener: parent_socket,
                        guest_vsock_cid: cid,
                    },
                    fd,
                ));
            }
            Err(err_code) => {
                let _ = nix::unistd::close(fd);

                // EADDRINUSE means the cid is in-use, we fail on any error
                // other than EADDRINUSE
                if err_code != nix::Error::EADDRINUSE {
                    return Err(format!(
                        "unable to ioctl vhost-vsock device. Error code {err_code}"
                    ));
                }
            }
        }
    }
    Err(format!("unable to get available CID for the guest"))
}

#[derive(Debug, Eq, PartialEq)]
enum GPUCount {
    All,
    Count(usize),
}

fn parse_gpu_count(value: String) -> Result<GPUCount, String> {
    let value = value.trim();
    if value == "all" {
        return Ok(GPUCount::All);
    }
    let count = value.parse::<usize>().map_err(|error| {
        format!(
            "{} must be a positive integer or \"all\": {error}",
            constants::GPU_COUNT_ENV_VAR
        )
    })?;
    if count == 0 {
        return Err(format!(
            "{} must be greater than zero",
            constants::GPU_COUNT_ENV_VAR
        ));
    }
    Ok(GPUCount::Count(count))
}

#[allow(unused)]
pub fn env_or_default(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{parse_gpu_bdfs, parse_gpu_count, GPUCount};
    use crate::utils::qemu::build_pcie_root_port;
    use std::collections::HashMap;
    use std::collections::HashSet;

    #[test]
    fn parses_multiple_gpu_bdfs() {
        assert_eq!(
            parse_gpu_bdfs("0000:21:00.0, 0000:81:00.0"),
            vec!["0000:21:00.0", "0000:81:00.0"],
        );
    }

    #[test]
    fn parses_single_gpu_bdf() {
        assert_eq!(parse_gpu_bdfs("0000:21:00.0"), vec!["0000:21:00.0"],)
    }

    #[test]
    fn empty_gpu_bdfs_produce_no_devices() {
        assert!(parse_gpu_bdfs(" , ").is_empty());
    }

    #[test]
    fn parses_gpu_count() {
        assert_eq!(parse_gpu_count("all".to_string()).unwrap(), GPUCount::All);
        assert_eq!(
            parse_gpu_count(" 2 ".to_string()).unwrap(),
            GPUCount::Count(2)
        );
        assert!(parse_gpu_count("0".to_string()).is_err());
        assert!(parse_gpu_count(String::new()).is_err());
        assert!(parse_gpu_count("two".to_string()).is_err());
    }

    #[test]
    fn gpu_root_ports_have_unique_topology() {
        assert_eq!(
            build_pcie_root_port(0),
            "pcie-root-port,id=pci.1,bus=pcie.0,addr=0x2,chassis=1,slot=1"
        );
        assert_eq!(
            build_pcie_root_port(1),
            "pcie-root-port,id=pci.2,bus=pcie.0,addr=0x3,chassis=2,slot=2"
        );
    }

    #[allow(unused)]
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

    #[allow(unused)]
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
