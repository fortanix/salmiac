/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use log::info;
use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::libc;
use nix::sys::stat::Mode;

pub(crate) const IOMMU_DEVICE_PATH: &str = "/dev/iommu";
pub(crate) const IOMMUFD_ID: &str = "iommufd0";
const VFIO_DEVICE_DIR: &str = "/dev/vfio/devices";
const VFIO_SYSFS_CLASS_DIR: &str = "/sys/class/vfio-dev";
const VFIO_DEVICE_BIND_IOMMUFD_NR: u8 = 118;

#[repr(C, align(8))]
#[derive(Default)]
struct AlignedU64(pub u64);

// See the link below for the structure necessary to bind iommu.
// https://github.com/torvalds/linux/blob/1b78070aaef63512688aebfbc82365ef9d6660f1/include/uapi/linux/vfio.h#L931
// Info: https://github.com/torvalds/linux/blob/master/Documentation/driver-api/vfio.rst#device-cdev-example
#[repr(C)]
#[derive(Default)]
struct VfioDeviceBindIommufd {
    argsz: u32,
    flags: u32,
    iommufd: i32,
    out_devid: u32,
    token_uuid_ptr: AlignedU64,
}

nix::ioctl_readwrite_bad!(
    vfio_device_bind_iommufd,
    nix::request_code_none!(b';', VFIO_DEVICE_BIND_IOMMUFD_NR),
    VfioDeviceBindIommufd
);

pub(crate) struct VfioGpuDevice {
    pub bdf: String,
    pub sysfs_path: PathBuf,
    pub file: File,
}

pub(crate) fn require_file<P: AsRef<OsStr>>(description: &str, path: P) -> Result<(), String> {
    let path_ref = path.as_ref();
    if Path::new(path_ref).exists() {
        Ok(())
    } else {
        Err(format!("{description} not found at {path_ref:?}"))
    }
}

const MIB: u64 = 1024 * 1024;
const MIN_PCI_MMIO64_MB: u64 = 256 * 1024;
const OTHER_DEVICES_HEADROOM_MB: u64 = 64 * 1024;
const IORESOURCE_MEM: u64 = 0x0000_0200;
const IORESOURCE_MEM_64: u64 = 0x0010_0000;

/// Calculates the 64-bit PCI MMIO aperture required by the selected GPUs.
///
/// Reads BAR0 through BAR5 from each GPU's sysfs `resource` file, sums their
/// 64-bit MMIO address-space requirements, adds alignment headroom, and rounds the result
/// up to a supported power-of-two aperture size.
///
/// See: https://docs.kernel.org/PCI/sysfs-pci.html
pub(crate) fn pci_mmio64_mb(gpus: &[String]) -> Result<u64, String> {
    let gpu_resources = gpus
        .iter()
        .map(|bdf| {
            (
                bdf.as_str(),
                PathBuf::from(format!("/sys/bus/pci/devices/{bdf}/resource")),
            )
        })
        .collect::<Vec<_>>();
    pci_mmio64_mb_from_resource_paths(&gpu_resources)
}

pub(crate) fn pci_mmio64_mb_from_vfio_devices(gpus: &[VfioGpuDevice]) -> Result<u64, String> {
    let gpu_resources = gpus
        .iter()
        .map(|gpu| (gpu.bdf.as_str(), gpu.sysfs_path.join("resource")))
        .collect::<Vec<_>>();
    pci_mmio64_mb_from_resource_paths(&gpu_resources)
}

fn pci_mmio64_mb_from_resource_paths(gpu_resources: &[(&str, PathBuf)]) -> Result<u64, String> {
    let mut bar_total = 0_u64;
    for (bdf, resource_path) in gpu_resources {
        let resources = fs::read_to_string(resource_path).map_err(|error| {
            format!(
                "Failed to read GPU {bdf} BAR resources from {}: {error}",
                resource_path.display()
            )
        })?;
        bar_total = bar_total
            .checked_add(parse_gpu_bar_total(&resources)?)
            .ok_or_else(|| "GPU BAR size total overflowed u64".to_string())?;
    }

    let size_mb = pci_mmio64_mb_from_bar_total(bar_total)?;
    info!(
        "Configured PCI MMIO64 window at {} MiB for {} GPU(s) with {} MiB of BAR resources",
        size_mb,
        gpu_resources.len(),
        bar_total / MIB,
    );
    Ok(size_mb)
}

/// Returns the combined size of BAR0 through BAR5 from one PCI device's
/// sysfs `resource` file.
///
/// Each resource line has the following format:
///
/// `<start address> <end address> <flags>`
///
/// Resource bounds are inclusive, so an assigned BAR has size
/// `end - start + 1`.
/// Unassigned resources (represented by zero or non-increasing bounds) are ignored.
///
/// Example:
///
/// `0x0000215000000000 0x0000215000ffffff 0x000000000014220c`
/// `0x0000200000000000 0x0000201fffffffff 0x000000000014220c`
fn parse_gpu_bar_total(resources: &str) -> Result<u64, String> {
    resources.lines().take(6).try_fold(0_u64, |total, line| {
        let mut fields = line.split_whitespace();
        let start = parse_pci_resource_value(fields.next(), line)?;
        let end = parse_pci_resource_value(fields.next(), line)?;
        let flags = parse_pci_resource_value(fields.next(), line)?;

        let mmio64_flags = IORESOURCE_MEM | IORESOURCE_MEM_64;
        let is_mmio64 = flags & mmio64_flags == mmio64_flags;

        if !is_mmio64 || (start == 0 && end == 0) {
            return Ok(total);
        }

        if end < start {
            return Err(format!(
                "Invalid PCI BAR resource range: start={start:#x}, end={end:#x}"
            ));
        }

        let size = end
            .checked_sub(start) // underflow checked above
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| format!("PCI BAR size overflow in {line:?}"))?;

        total
            .checked_add(size)
            .ok_or_else(|| "GPU MMIO64 total overflowed u64".to_string())
    })
}

fn parse_pci_resource_value(value: Option<&str>, line: &str) -> Result<u64, String> {
    let value = value.ok_or_else(|| format!("Malformed PCI resource line {line:?}"))?;
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| format!("Invalid PCI resource value {value:?}: {error}"))
}

fn pci_mmio64_mb_from_bar_total(bar_total: u64) -> Result<u64, String> {
    if bar_total == 0 {
        return Err("No 64-bit GPU BAR resources were found".to_string());
    }

    let bar_mb = bar_total / MIB;
    let need_mb = bar_mb
        .checked_add(bar_mb / 4) // Add 25% headroom
        .and_then(|value| value.checked_add(OTHER_DEVICES_HEADROOM_MB)) // The headroom of PCI devices that are not passed-through
        .ok_or_else(|| "PCI MMIO64 size calculation overflowed u64".to_string())?;

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
    if !size_mb.is_power_of_two() {
        return Err(format!(
            "Computed PCI MMIO64 window {size_mb} MiB is not a power of two"
        ));
    }
    Ok(())
}

// Builds pcie root port string for given device at index.
pub(crate) fn build_pcie_root_port(index: usize) -> String {
    let number = index + 1;
    format!(
        "pcie-root-port,id=pci.{number},bus=pcie.0,addr=0x{:x},chassis={number},slot={number}",
        number + 1,
    )
}

// Builds an iommufd object backed by an already-open file descriptor.
pub(crate) fn build_iommufd_object(fd: RawFd) -> String {
    format!("iommufd,id={IOMMUFD_ID},fd={fd}")
}

// Builds a vfio-pci device backed by an already-open VFIO cdev descriptor.
// Note that, without explicit `id` argument, qemu is crashing.
pub(crate) fn build_vfio_iommu_arg(fd: RawFd, index: usize) -> String {
    format!(
        "vfio-pci,id=gpu.{},fd={},bus=pci.{},iommufd={},romfile=",
        index + 1,
        fd,
        index + 1,
        IOMMUFD_ID,
    )
}

pub(crate) fn open_iommufd() -> Result<File, String> {
    open_inheritable_file(Path::new(IOMMU_DEVICE_PATH))
}

/// Resolves a PCI BDF to its VFIO device cdev and opens it read-write.
///
/// The kernel exposes the BDF-to-cdev mapping as
/// `/sys/bus/pci/devices/<BDF>/vfio-dev/vfioX`. The cdev major and minor
/// numbers are verified against `/dev/vfio/devices/vfioX` before returning.
pub(crate) fn open_vfio_device(bdf: &str) -> Result<File, String> {
    let bdf = normalize_pci_bdf(bdf)?;
    let pci_device_path = PathBuf::from(format!("/sys/bus/pci/devices/{bdf}"));
    require_file("GPU PCI device", &pci_device_path)?;

    let vfio_dev_dir = pci_device_path.join("vfio-dev");
    let mut vfio_entries = fs::read_dir(&vfio_dev_dir)
        .map_err(|error| format!("Failed to read {}: {error}", vfio_dev_dir.display()))?
        .filter_map(|entry| match entry {
            Ok(entry) if is_vfio_cdev_name(entry.file_name().as_os_str()) => Some(Ok(entry)),
            Ok(_) => None,
            Err(error) => Some(Err(format!(
                "Failed to read an entry in {}: {error}",
                vfio_dev_dir.display()
            ))),
        })
        .collect::<Result<Vec<_>, String>>()?;

    if vfio_entries.len() != 1 {
        return Err(format!(
            "Expected exactly one VFIO cdev entry in {}, found {}",
            vfio_dev_dir.display(),
            vfio_entries.len()
        ));
    }

    let vfio_entry = vfio_entries.pop().expect("vfio_entry"); // verified above
    let sysfs_dev_path = vfio_entry.path().join("dev");
    let expected_device = fs::read_to_string(&sysfs_dev_path)
        .map_err(|error| format!("Failed to read {}: {error}", sysfs_dev_path.display()))?;
    let (expected_major, expected_minor) =
        parse_device_number(&expected_device).map_err(|error| {
            format!(
                "Invalid device number in {}: {error}",
                sysfs_dev_path.display()
            )
        })?;

    let cdev_path = PathBuf::from(VFIO_DEVICE_DIR).join(&vfio_entry.file_name());
    open_vfio_cdev(&cdev_path, Some((expected_major, expected_minor)))
}

/// Enumerates VFIO PCI GPU devices and resolves their real sysfs paths.
///
/// `count` selects exactly that many devices and fails if fewer are available.
/// `None` selects all available devices.
pub(crate) fn enumerate_vfio_gpu_devices(
    count: Option<usize>,
) -> Result<Vec<VfioGpuDevice>, String> {
    let device_dir = Path::new(VFIO_DEVICE_DIR);
    let mut cdev_names = fs::read_dir(device_dir)
        .map_err(|error| format!("Failed to read {}: {error}", device_dir.display()))?
        .filter_map(|entry| match entry {
            // All devices in this directory are expected to be character devices.
            // See: https://docs.kernel.org/driver-api/vfio.html#vfio-device-cdev
            Ok(entry) => Some(Ok(entry.file_name())),
            Err(error) => Some(Err(format!(
                "Failed to read an entry in {}: {error}",
                device_dir.display()
            ))),
        })
        .collect::<Result<Vec<_>, String>>()?;
    cdev_names.sort_by_key(|name| vfio_cdev_number(name.as_os_str()));

    let probe_iommufd = open_iommufd()?;
    let mut gpus = Vec::new();
    for cdev_name in cdev_names {
        // How sysfs entry is resolved for a device under `/dev/vfio/devices/<cdev_name>`
        //  * Visit its class device: `/sys/class/vfio-dev/<cdev_name>/device`.
        //  * Follow class device link to its sysfs device entry: `/sys/devices/pci0000:XX/0000:XX:XX.X/{bdf}`
        let class_device_path = Path::new(VFIO_SYSFS_CLASS_DIR)
            .join(&cdev_name)
            .join("device");
        let sysfs_path = fs::canonicalize(&class_device_path).map_err(|error| {
            format!(
                "Failed to resolve VFIO device sysfs path {}: {error}",
                class_device_path.display()
            )
        })?;
        if !is_pci_gpu(&sysfs_path)? {
            continue;
        }

        let bdf = sysfs_path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| format!("Invalid PCI sysfs path {}", sysfs_path.display()))?;
        let bdf = normalize_pci_bdf(bdf)?;
        let sysfs_dev_path = sysfs_path.join("vfio-dev").join(&cdev_name).join("dev");
        let expected_device = fs::read_to_string(&sysfs_dev_path)
            .map_err(|error| format!("Failed to read {}: {error}", sysfs_dev_path.display()))?;
        let expected_device = parse_device_number(&expected_device).map_err(|error| {
            format!(
                "Invalid device number in {}: {error}",
                sysfs_dev_path.display()
            )
        })?;

        // Try to bind to the device to check its availability.
        let cdev_path = device_dir.join(&cdev_name);
        if !probe_vfio_device_availability(&cdev_path, expected_device, &probe_iommufd, &bdf)? {
            continue;
        }

        // Final open to be passed to qemu. Omit expected_device as it should be verified above.
        let file = open_vfio_cdev(&cdev_path, None)?;
        gpus.push(VfioGpuDevice {
            bdf,
            sysfs_path,
            file,
        });

        if count.is_some_and(|count| gpus.len() == count) {
            break;
        }
    }

    if let Some(count) = count {
        if gpus.len() != count {
            return Err(format!(
                "Requested {count} GPU(s), but found only {} under {VFIO_DEVICE_DIR}",
                gpus.len()
            ));
        }
    } else if gpus.is_empty() {
        return Err(format!("No GPU devices found under {VFIO_DEVICE_DIR}"));
    }

    Ok(gpus)
}

/// Tries to bind the VFIO device with a temporary iommufd.
fn probe_vfio_device_availability(
    cdev_path: &Path,
    expected_device: (u64, u64),
    iommufd: &File,
    bdf: &str,
) -> Result<bool, String> {
    // Open a temporary device descriptor instead of accepting the descriptor that
    // will later be passed to QEMU.
    // The deliberate choice of fresh opening cdev_path is to UNBIND the device
    // by means of closing the relavent file descriptor if it successfully binds.
    // See: https://github.com/torvalds/linux/blob/1b78070aaef63512688aebfbc82365ef9d6660f1/include/uapi/linux/vfio.h#L921
    let vfio_device = open_vfio_cdev(cdev_path, Some(expected_device))?;
    let mut bind = VfioDeviceBindIommufd {
        argsz: std::mem::size_of::<VfioDeviceBindIommufd>() as u32,
        iommufd: iommufd.as_raw_fd(),
        ..Default::default()
    };

    match unsafe { vfio_device_bind_iommufd(vfio_device.as_raw_fd(), &mut bind) } {
        Ok(_) => {
            // Un-binds when this file is closed.
            drop(vfio_device);
            Ok(true)
        }
        Err(error) if is_vfio_device_busy_errno(error) => {
            info!(
                "Skipping busy VFIO GPU {} at {}: {}",
                bdf,
                cdev_path.display(),
                error
            );
            Ok(false)
        }
        Err(error) => Err(format!(
            "Failed to bind VFIO GPU {bdf} at {} to temporary iommufd: {error}",
            cdev_path.display()
        )),
    }
}

fn is_vfio_device_busy_errno(errno: Errno) -> bool {
    errno == Errno::EBUSY || errno == Errno::EINVAL
}

fn vfio_cdev_number(name: &OsStr) -> u64 {
    name.to_str()
        .and_then(|name| name.strip_prefix("vfio"))
        .and_then(|number| number.parse().ok())
        .unwrap_or(u64::MAX)
}

fn is_pci_gpu(sysfs_path: &Path) -> Result<bool, String> {
    let class_path = sysfs_path.join("class");
    let class = fs::read_to_string(&class_path)
        .map_err(|error| format!("Failed to read {}: {error}", class_path.display()))?;
    let class = u32::from_str_radix(class.trim().trim_start_matches("0x"), 16)
        .map_err(|error| format!("Invalid PCI class in {}: {error}", class_path.display()))?;
    // 0x03XX represents a DISPLAY device
    // Source: https://github.com/torvalds/linux/blob/1b78070aaef63512688aebfbc82365ef9d6660f1/include/linux/pci_ids.h#L38
    Ok(class >> 16 == 0x03)
}

/// Opens a VFIO character device with a descriptor that QEMU can inherit.
///
/// If `expected_device` is provided, the cdev major and minor numbers must
/// match before the file is returned.
pub(crate) fn open_vfio_cdev(
    cdev_path: &Path,
    expected_device: Option<(u64, u64)>,
) -> Result<File, String> {
    let file = open_inheritable_file(cdev_path)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Failed to inspect {}: {error}", cdev_path.display()))?;
    if !metadata.file_type().is_char_device() {
        return Err(format!("{} is not a character device", cdev_path.display()));
    }

    if let Some((expected_major, expected_minor)) = expected_device {
        let device = metadata.rdev();
        let major = libc::major(device) as u64;
        let minor = libc::minor(device) as u64;
        if (major, minor) != (expected_major, expected_minor) {
            return Err(format!(
                "VFIO cdev {} has device number {}:{}, expected {}:{}",
                cdev_path.display(),
                major,
                minor,
                expected_major,
                expected_minor
            ));
        }
    }

    Ok(file)
}

fn open_inheritable_file(path: &Path) -> Result<File, String> {
    // QEMU receives this descriptor on its command line (`fd` arg of device for example),
    // so the descriptor must remain open across exec. O_CLOEXEC is intentionally omitted.
    // Rust's File/OpenOptions APIs add it automatically on Unix.
    let fd = open(path, OFlag::O_RDWR, Mode::empty())
        .map_err(|error| format!("Failed to open {}: {error}", path.display()))?;

    Ok(File::from(fd))
}

fn normalize_pci_bdf(bdf: &str) -> Result<String, String> {
    let bdf = bdf.trim();
    let (slot, function) = bdf
        .rsplit_once('.')
        .ok_or_else(|| format!("Invalid PCI BDF {bdf:?}"))?;
    let mut components = slot.split(':');
    let domain = parse_hex_component(components.next(), "domain", bdf)?;
    let bus = parse_hex_component(components.next(), "bus", bdf)?;
    let device = parse_hex_component(components.next(), "device", bdf)?;
    if components.next().is_some() {
        return Err(format!("Invalid PCI BDF {bdf:?}"));
    }
    let function = u8::from_str_radix(function, 16)
        .map_err(|error| format!("Invalid PCI function in BDF {bdf:?}: {error}"))?;

    if domain > u16::MAX as u64 || bus > u8::MAX as u64 || device > 0x1f || function > 7 {
        return Err(format!("PCI BDF is out of range: {bdf:?}"));
    }

    Ok(format!("{domain:04x}:{bus:02x}:{device:02x}.{function:x}"))
}

fn parse_hex_component(component: Option<&str>, name: &str, bdf: &str) -> Result<u64, String> {
    let component = component.ok_or_else(|| format!("Missing PCI {name} in BDF {bdf:?}"))?;
    u64::from_str_radix(component, 16)
        .map_err(|error| format!("Invalid PCI {name} in BDF {bdf:?}: {error}"))
}

fn is_vfio_cdev_name(name: &OsStr) -> bool {
    name.as_bytes()
        .strip_prefix(b"vfio")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.iter().all(u8::is_ascii_digit))
}

fn parse_device_number(value: &str) -> Result<(u64, u64), String> {
    let (major, minor) = value
        .trim()
        .split_once(':')
        .ok_or_else(|| format!("Expected major:minor, found {value:?}"))?;
    let major = major
        .parse::<u64>()
        .map_err(|error| format!("Invalid major number {major:?}: {error}"))?;
    let minor = minor
        .parse::<u64>()
        .map_err(|error| format!("Invalid minor number {minor:?}: {error}"))?;
    Ok((major, minor))
}

#[cfg(test)]
mod tests {
    use super::{
        is_vfio_cdev_name, normalize_pci_bdf, parse_device_number, parse_gpu_bar_total,
        pci_mmio64_mb_from_bar_total, MIB,
    };
    use std::ffi::OsStr;

    #[test]
    fn normalizes_pci_bdf() {
        assert_eq!(normalize_pci_bdf(" 000A:0B:1C.7 ").unwrap(), "000a:0b:1c.7");
    }

    #[test]
    fn rejects_out_of_range_pci_bdf() {
        assert!(normalize_pci_bdf("0000:17:20.0").is_err());
        assert!(normalize_pci_bdf("0000:17:00.8").is_err());
    }

    #[test]
    fn recognizes_vfio_cdev_names() {
        assert!(is_vfio_cdev_name(OsStr::new("vfio0")));
        assert!(is_vfio_cdev_name(OsStr::new("vfio123")));
        assert!(!is_vfio_cdev_name(OsStr::new("vfio")));
        assert!(!is_vfio_cdev_name(OsStr::new("vfio12x")));
    }

    #[test]
    fn parses_sysfs_device_number() {
        assert_eq!(parse_device_number("511:13\n").unwrap(), (511, 13));
        assert!(parse_device_number("511").is_err());
    }

    #[test]
    fn sums_only_64_bit_mmio_gpu_bars() {
        let resources = concat!(
            "0x1000 0x1fff 0x00100200\n", // 64-bit MMIO: included
            "0x2000 0x3fff 0x00000200\n", // 32-bit MMIO: excluded
            "0x0 0x0 0x00100200\n",       // unassigned: excluded
            "0x4000 0x7fff 0x00100200\n", // 64-bit MMIO: included
            "0x8000 0x8fff 0x00000100\n", // I/O port: excluded
            "0x0 0x0 0x0\n",
            "0x9000 0xffff 0x00100200\n", // seventh resource: ignored
        );
        assert_eq!(parse_gpu_bar_total(resources).unwrap(), 0x5000);
    }

    #[test]
    fn sizes_mmio_window_from_bar_total() {
        assert_eq!(
            pci_mmio64_mb_from_bar_total(128 * 1024 * MIB).unwrap(),
            256 * 1024
        );
        assert_eq!(
            pci_mmio64_mb_from_bar_total(256 * 1024 * MIB).unwrap(),
            512 * 1024
        );
    }

    #[test]
    fn fails_when_no_64_bit_bars_are_found() {
        assert_eq!(
            pci_mmio64_mb_from_bar_total(0).unwrap_err(),
            "No 64-bit GPU BAR resources were found"
        );
    }
}
