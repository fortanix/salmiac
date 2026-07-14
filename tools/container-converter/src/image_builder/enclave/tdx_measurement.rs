/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use api_model::HexString;
use api_model::{tdx::TdxEnclavesMeasurements, ByteUnit};
use log::debug;
use tdx_measure::{BootConfig, ImageConfig, Machine, QemuShape};

use crate::{ConverterError, Result, SALMIAC_TEMP_DIR};

const QEMU_SOURCE_TAR_HASH: &str =
    "784b296ff29c1417aa72323abcb2d2ea9ab9771724f577dcd785c3b04f21e176";
const QEMU_SOURCE_TAR_URL: &str = "https://download.qemu.org/qemu-10.2.2.tar.xz";
const GUEST_OS: &str = "ubuntu:24.04";
const MEMORY_BACKEND_ID: &str = "mem0";
const VSOCK_DEVICE: &str = "vhost-vsock-pci,guest-cid=3"; // Mock CID, the value does not impact the measurements
const QEMU_CPU_TYPE: &str = "max,phys-bits=46"; // The measurements do not change on or above 46 bits width.
const QEMU_ACCEL_MODE: &str = "tcg"; // For emulating runtime cpu configuration with above phys-bits address space to match the runtime-measurements
const ACPI_TABLES_PATH: &str = ""; // Empty path skips copying the actual acpi tables binary
const PCI_HOLE_SIZE_GLOBAL: &str = "q35-pcihost.pci-hole64-size=256G"; // Should match the runtime configuration value in ${SALMIAC_DIR}/vsock-proxy/parent/src/platform/tdx.rs
const MOCK_GPU_DEVICE: &str = "e1000e,bus=pci.1,addr=0x0,romfile="; // To mock the GPU that would be available at runtime
const GPU_PCI_BUS_DEVICE: &str = "pcie-root-port,id=pci.1,bus=pcie.0";
const DEFAULT_SERIAL_DEVICE: &str = "mon:stdio";
const FW_CFG_MMIO64: &str = "name=opt/ovmf/X-PciMmio64Mb,string=262144";

pub(crate) struct TdxMeasurementInputs<'a> {
    pub ovmf: &'a Path,
    pub kernel: &'a Path,
    pub initrd: &'a Path,
    pub cmdline: Option<&'a str>,
    pub vcpus: u8,
    pub memory: ByteUnit,
    pub enable_gpu_passthrough: bool,
}

pub(crate) async fn compute_tdx_launch_measurement(
    inputs: &TdxMeasurementInputs<'_>,
) -> Result<TdxEnclavesMeasurements> {
    let temp_ovmf_dir = tempfile::tempdir_in(SALMIAC_TEMP_DIR.to_string())
        .and_then(|temp_dir| {
            fs::set_permissions(temp_dir.path(), std::fs::Permissions::from_mode(0o444))?;
            Ok(temp_dir)
        })
        .map_err(|error| ConverterError {
            message: format!(
                "Failed to create temporary folder to hold OVMF for TDX build measurements : {}",
                error
            ),
            kind: crate::ConverterErrorKind::EnclaveImageCreation,
        })?;

    let ovmf_path = temp_ovmf_dir.path().join("OVMF.fd");
    fs::copy(inputs.ovmf, &ovmf_path).map_err(|error| ConverterError {
        message: format!(
            "Failed to copy OVMF to temporary folder for TDX build measurements : {}",
            error
        ),
        kind: crate::ConverterErrorKind::EnclaveImageCreation,
    })?;

    let ovmf = ovmf_path.display().to_string();

    let kernel = inputs.kernel.display().to_string();

    let mut vm_objects = Vec::new();
    // "reserve=off" to prevent qemu from reserving the memory during conversion
    let memory_backend_device = format!(
        "memory-backend-ram,id={},size={}M,reserve=off",
        MEMORY_BACKEND_ID,
        inputs.memory.to_mb()
    );
    vm_objects.push(memory_backend_device);

    // NOTE: Be mindful about the order of devices and ensure that the order of devices here matches the
    //     - launch configuration in vsock-proxy to reproduce conversion time measurements at runtime.
    let mut vm_devices = Vec::new();
    let machine_arg = format!(
        "q35,kernel_irqchip=split,memory-backend={MEMORY_BACKEND_ID},hpet=off,smm=off,pic=off",
    );
    let mut vm_globals = Vec::new();
    let mut vm_fw_cfg = Vec::new();

    if inputs.enable_gpu_passthrough {
        vm_globals.push(PCI_HOLE_SIZE_GLOBAL.to_string());
        vm_fw_cfg.push(FW_CFG_MMIO64.to_string());
        vm_devices.push(GPU_PCI_BUS_DEVICE.to_string());
        vm_devices.push(MOCK_GPU_DEVICE.to_string());
    }
    vm_devices.push(VSOCK_DEVICE.to_string());

    let initrd = inputs.initrd.display().to_string();
    let machine = Machine::builder()
        .cpu_count(inputs.vcpus)
        .memory_size(inputs.memory.to_inner())
        .firmware(&ovmf)
        .kernel(&kernel)
        .acpi_tables(ACPI_TABLES_PATH)
        .kernel_cmdline(inputs.cmdline.unwrap_or(""))
        .direct_boot(true)
        .initrd(&initrd)
        .distribution(GUEST_OS)
        .qemu_source_url(QEMU_SOURCE_TAR_URL)
        .qemu_source_sha256(QEMU_SOURCE_TAR_HASH)
        .create_acpi_table(true)
        .image_config(
            ImageConfig::builder()
                .boot_config(
                    BootConfig::builder()
                        .acpi_tables(ACPI_TABLES_PATH.to_string()) // Pass empty string as this is ignored
                        .cpus(inputs.vcpus)
                        .memory(format!("{}M", inputs.memory.to_mb()))
                        .bios(ovmf.clone())
                        .qemu(QemuShape {
                            machine: machine_arg,
                            accel: QEMU_ACCEL_MODE.to_string(),
                            globals: vm_globals,
                            objects: vm_objects,
                            netdevs: vec![],
                            devices: vm_devices,
                            fw_cfg: vm_fw_cfg,
                            cpu: QEMU_CPU_TYPE.to_string(),
                            serial: Some(DEFAULT_SERIAL_DEVICE.to_string()),
                        })
                        .build(),
                )
                .build(),
        )
        .metadata_path(Path::new(""))
        .patch_kernel(false)
        .path_boot_xxxx("")
        .boot_order("")
        .table_loader("")
        .rsdp("")
        .build();

    let measurements = machine.measure().map_err(|error| ConverterError {
        message: format!("Failed to get build-time measurements : {}", error),
        kind: crate::ConverterErrorKind::EnclaveImageCreation,
    })?;
    let measurements = TdxEnclavesMeasurements {
        mrtd: HexString::new(measurements.mrtd),
        rtmr0: HexString::new(measurements.rtmr0),
        rtmr1: HexString::new(measurements.rtmr1),
        rtmr2: HexString::new(measurements.rtmr2),
        rtmr3: HexString::new(vec![0x0; 48]),
    };
    debug!("TDX Machine measurements:");
    debug!("MRTD: {}", &measurements.mrtd);
    debug!("RTMR0: {}", &measurements.rtmr0);
    debug!("RTMR1: {}", &measurements.rtmr1);
    debug!("RTMR2: {}", &measurements.rtmr2);
    debug!("RTMR3: {}", &measurements.rtmr3);

    Ok(measurements)
}
