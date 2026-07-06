/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::path::Path;

use api_model::HexString;
use api_model::{tdx::TdxEnclavesMeasurements, ByteUnit};
use log::info;
use tdx_measure::{BootConfig, ImageConfig, Machine, QemuShape};
use tdxguest_acpi_tables::BuildOptions;

const QEMU_SOURCE_TAR_HASH: &str =
    "784b296ff29c1417aa72323abcb2d2ea9ab9771724f577dcd785c3b04f21e176";
const QEMU_SOURCE_TAR_URL: &str = "https://download.qemu.org/qemu-10.2.2.tar.xz";
const GUEST_OS: &str = "ubuntu:24.04";
const MEMORY_BACKEND_ID: &str = "mem0";
const VSOCK_DEVICE: &str = "vhost-vsock-pci,guest-cid=3"; // Mock CID, the value does not impact the measurements
const QEMU_ACCEL_MODE: &str = "kvm";
const QEMU_CPU_TYPE: &str = "host";
const ACPI_TABLES_PATH: &str = ""; // Empty path skips copying the actual acpi tables binary

pub(crate) struct TdxMeasurementInputs<'a> {
    pub ovmf: &'a Path,
    pub kernel: &'a Path,
    pub initrd: &'a Path,
    pub cmdline: Option<&'a str>,
    pub vcpus: u8,
    pub memory: ByteUnit,
    pub gpu_passthrough: bool,
}

pub(crate) async fn compute_tdx_launch_measurement(
    inputs: &TdxMeasurementInputs<'_>,
) -> Result<TdxEnclavesMeasurements, String> {
    let ovmf = inputs.ovmf.display().to_string();
    let kernel = inputs.kernel.display().to_string();

    let acpi_tables_temp = {
        let tempfile = tempfile::NamedTempFile::with_prefix("acpi_tables")
            .map_err(|err| format!("Failed to create tempfile: {}", err.to_string()))?;
        let mut build_options = BuildOptions {
            cpu_count: inputs.vcpus as usize,
            mem_size_gb: inputs.memory.to_gb(),
            pci_count: 1,
            ..Default::default()
        };
        if inputs.gpu_passthrough {
            build_options.pcie = true;
            build_options.nvram_gb = 256;
            build_options.pci64_size_mb = 131120;
        }
        info!("ACPI table build options: {:?}", build_options);
        tdxguest_acpi_tables::build(tempfile.path(), build_options)
            .map_err(|err| format!("Faild to build acpi tables: {}", err.to_string()))?;
        tempfile
    };
    let mut vm_objects = Vec::new();
    let memory_backend_device = format!(
        "memory-backend-ram,id={},size={}M",
        MEMORY_BACKEND_ID,
        inputs.memory.to_mb()
    );
    vm_objects.push(memory_backend_device);
    let mut vm_devices = Vec::new();
    // TODO: Pending device addtion for gpu enabled devices
    vm_devices.push(VSOCK_DEVICE.to_string());
    let machine_arg = format!(
        "q35,kernel_irqchip=split,memory-backend={MEMORY_BACKEND_ID},hpet=off,smm=off,pic=off",
    );

    let initrd = inputs.initrd.display().to_string();
    let cmdline = inputs.cmdline.ok_or("missing cmdline")?;
    let acpi_tables_path = acpi_tables_temp.path().to_str()
        .ok_or("Unable to convert acpi tables path")?;

    let machine = Machine::builder()
        .cpu_count(inputs.vcpus)
        .memory_size(inputs.memory.to_inner())
        .firmware(&ovmf)
        .kernel(&kernel)
        .acpi_tables(acpi_tables_path)
        .kernel_cmdline(cmdline)
        .direct_boot(true)
        .initrd(&initrd)
        .distribution(GUEST_OS)
        // .qemu_source_url(QEMU_SOURCE_TAR_URL)
        // .qemu_source_sha256(QEMU_SOURCE_TAR_HASH)
        .create_acpi_table(false)
        // .image_config(
        //     ImageConfig::builder()
        //         .boot_config(
        //             BootConfig::builder()
        //                 .acpi_tables(ACPI_TABLES_PATH.to_string()) // Pass empty string as this is ignored
        //                 .cpus(inputs.vcpus)
        //                 .memory(format!("{}M", inputs.memory.to_mb()))
        //                 .bios(inputs.ovmf.display().to_string())
        //                 .qemu(QemuShape {
        //                     machine: machine_arg,
        //                     accel: QEMU_ACCEL_MODE.to_string(),
        //                     globals: vec![],
        //                     objects: vm_objects,
        //                     netdevs: vec![],
        //                     devices: vm_devices,
        //                     fw_cfg: vec![],
        //                     cpu: QEMU_CPU_TYPE.to_string(),
        //                     serial: None,
        //                 })
        //                 .build(),
        //         )
        //         .build(),
        // )
        .metadata_path(Path::new(""))
        .patch_kernel(false)
        .path_boot_xxxx("")
        .boot_order("")
        .table_loader("")
        .rsdp("")
        .build();

    let measurements = machine.measure().expect("should not fail");
    let measurements = TdxEnclavesMeasurements {
        mrtd: HexString::new(measurements.mrtd),
        rtmr0: HexString::new(measurements.rtmr0),
        rtmr1: HexString::new(measurements.rtmr1),
        rtmr2: HexString::new(measurements.rtmr2),
        rtmr3: HexString::new(Vec::new()),
    };
    info!("TDX Machine measurements:");
    info!("MRTD: {}", &measurements.mrtd);
    info!("RTMR0: {}", &measurements.rtmr0);
    info!("RTMR1: {}", &measurements.rtmr1);
    info!("RTMR2: {}", &measurements.rtmr2);

    Ok(measurements)
}
