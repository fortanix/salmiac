# Download OVMF and EFI boot stubb
ARG NVIDIA_DRIVER_BRANCH=595

FROM ubuntu:25.10 AS apt_extract
RUN DEBIAN_FRONTEND=noninteractive apt-get update

RUN mkdir -p /blob

RUN apt-get download systemd-boot-efi && \
dpkg -x systemd-boot-efi*.deb system_boot_efi_dir &&\
cp system_boot_efi_dir/usr/lib/systemd/boot/efi/linuxx64.efi.stub /blob

RUN apt-get download ovmf && \
dpkg -x ovmf*.deb ovmf_dir && \
cp ovmf_dir/usr/share/ovmf/OVMF.amdsev.fd /blob

FROM ubuntu:24.04 AS nvidia_userspace
ARG NVIDIA_DRIVER_BRANCH
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libnvidia-compute-${NVIDIA_DRIVER_BRANCH} \
        nvidia-utils-${NVIDIA_DRIVER_BRANCH} \
        nvidia-kernel-common-${NVIDIA_DRIVER_BRANCH} && \
    rm -rf /var/lib/apt/lists/*

COPY stage-nvidia-driver-payload.sh /usr/local/bin/stage-nvidia-driver-payload.sh
RUN bash -x /usr/local/bin/stage-nvidia-driver-payload.sh /nvidia-driver-payload

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y cryptsetup-bin

RUN mkdir -p /var/log/enclave-os

WORKDIR /app

COPY staging/server staging/parent-base.tar staging/enclave-base.tar staging/enclave-base-gpu.tar /app/

COPY --from=apt_extract /blob /opt/fortanix/enclave-os/blobs
COPY --from=nvidia_userspace /nvidia-driver-payload /opt/fortanix/enclave-os/nvidia-driver-payload

# Copy gpu disabled artifacts
COPY kernel_disabled_gpu/init /opt/fortanix/enclave-os/blobs/kernel_disabled_gpu/init
COPY kernel_disabled_gpu/.config /opt/fortanix/enclave-os/blobs/kernel_disabled_gpu/bzImage.config
COPY kernel_disabled_gpu/bzImage /opt/fortanix/enclave-os/blobs/kernel_disabled_gpu/bzImage

# Copy gpu enabled artifacts
COPY kernel_enabled_gpu/init /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/init
COPY kernel_enabled_gpu/.config /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/bzImage.config
COPY kernel_enabled_gpu/bzImage /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/bzImage
COPY kernel_enabled_gpu/nvidia-uvm.ko /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/nvidia-uvm.ko
COPY kernel_enabled_gpu/nvidia.ko /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/nvidia.ko
COPY kernel_enabled_gpu/nvidia-drm.ko /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/nvidia-drm.ko
COPY kernel_enabled_gpu/nvidia-modeset.ko /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/nvidia-modeset.ko

ENTRYPOINT [ "./server" ]
