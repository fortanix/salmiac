/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::fs;
use std::path::Path;

use log::{info, warn};

pub(crate) const DEVICE_PATH: &str = "/dev/iommu";
pub(crate) const IOMMUFD_ID: &str = "iommufd0";
pub(crate) const IOMMUFD_OBJECT: &str = "iommufd,id=iommufd0";

pub(crate) fn require_file(description: &str, path: &str) -> Result<(), String> {
    if Path::new(path).exists() {
        Ok(())
    } else {
        Err(format!("{description} not found at {path}"))
    }
}

const MIB: u64 = 1024 * 1024;
const MIN_PCI_MMIO64_MB: u64 = 256 * 1024;
const OTHER_DEVICES_HEADROOM_MB: u64 = 64 * 1024;
const FALLBACK_GPU_BAR_MB: u64 = 128 * 1024;
const MAX_PCI_MMIO64_MB: u64 = 8 * 1024 * 1024;
const IORESOURCE_MEM: u64 = 0x0000_0200;
const IORESOURCE_MEM_64: u64 = 0x0010_0000;

/// Calculates the 64-bit PCI MMIO aperture required by the selected GPUs.
///
/// Reads BAR0 through BAR5 from each GPU's sysfs `resource` file, sums their
/// 64-bit MMIO address-space requirements, adds alignment headroom, and rounds the result
/// up to a supported power-of-two aperture size.
///
/// If any resource file cannot be read, conservative sizing based on the
/// number of GPUs is used instead.
///
/// See: https://docs.kernel.org/PCI/sysfs-pci.html
pub(crate) fn pci_mmio64_mb(gpus: &[String]) -> Result<u64, String> {
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

    let size_mb =
        pci_mmio64_mb_from_bar_total(if all_resources_read { bar_total } else { 0 }, gpus.len())?;
    info!(
        "Configured PCI MMIO64 window at {} MiB for {} GPU(s) with {} MiB of BAR resources",
        size_mb,
        gpus.len(),
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
/// `end - start + 1`. Unassigned resources, represented by zero or otherwise
/// non-increasing bounds, contribute nothing.
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
                    .ok_or_else(|| "PCI MMIO64 fallback calculation overflowed u64".to_string())?,
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

// Builds pcie root port string for given device at index.
pub(crate) fn build_pcie_root_port(index: usize) -> String {
    let number = index + 1;
    format!(
        "pcie-root-port,id=pci.{number},bus=pcie.0,addr=0x{:x},chassis={number},slot={number}",
        number + 1,
    )
}

// Builds vfio-pci string for given bdf device at index
pub(crate) fn build_vfio_iommu_arg(bdf: &str, index: usize) -> String {
    format!(
        "vfio-pci,host={},bus=pci.{},iommufd={},romfile=",
        bdf,
        index + 1,
        IOMMUFD_ID,
    )
}

pub(crate) fn require_vfio_device(bdf: &str) -> Result<(), String> {
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
