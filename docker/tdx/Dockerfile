# Download OVMF and EFI boot stub
FROM ubuntu:25.10 AS apt_extract
RUN DEBIAN_FRONTEND=noninteractive apt-get update

RUN mkdir -p /blob

RUN apt-get download systemd-boot-efi \
    && dpkg -x systemd-boot-efi*.deb system_boot_efi_dir \
    && cp system_boot_efi_dir/usr/lib/systemd/boot/efi/linuxx64.efi.stub /blob

# RUN apt-get download ovmf-inteltdx \
#     && dpkg -x ovmf*.deb ovmf_dir \
#     && cp ovmf_dir/usr/share/ovmf/OVMF.inteltdx.fd /blob

FROM ubuntu:24.04 AS nvidia_userspace
ARG NVIDIA_DRIVER_BRANCH=595
ARG NVIDIA_DRIVER_BRANCH_PINNED=595.71.05-0ubuntu0.24.04.1
ARG UBUNTU_SNAPSHOT=20260601T000000Z
ENV DEBIAN_FRONTEND=noninteractive

# Restrict Ubuntu repositories used by the snapshot:
#   disabled components: noble-backports, universe
RUN sed -i \
        -e 's/ noble-backports//g' \
        -e 's/ universe//g' \
        /etc/apt/sources.list.d/ubuntu.sources

# Bootstrap HTTPS trust using the current archive first.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates

# Ubuntu security updates may publish newer NVIDIA libraries and firmware.
# Because the NVIDIA driver is supplied as a build artifact and requires specific
# older versions, use a repository snapshot to install the compatible packages.
RUN apt-get install \
        --update \
        --snapshot "${UBUNTU_SNAPSHOT}" \
        -y --no-install-recommends \
        libnvidia-compute-${NVIDIA_DRIVER_BRANCH}=${NVIDIA_DRIVER_BRANCH_PINNED} \
        nvidia-utils-${NVIDIA_DRIVER_BRANCH}=${NVIDIA_DRIVER_BRANCH_PINNED} \
        nvidia-kernel-common-${NVIDIA_DRIVER_BRANCH}=${NVIDIA_DRIVER_BRANCH_PINNED} \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY stage-nvidia-driver-payload.sh /usr/local/bin/stage-nvidia-driver-payload.sh
RUN bash -x /usr/local/bin/stage-nvidia-driver-payload.sh /nvidia-driver-payload

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y \
        cryptsetup-bin \
        python3 \
        docker-cli \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=apt_extract /blob /opt/fortanix/enclave-os/blobs
COPY --from=nvidia_userspace /nvidia-driver-payload /opt/fortanix/enclave-os/nvidia-driver-payload

# These need to be pulled in from Jenkins https://jenkins.fortanix.net/job/build-salmiac-kernel/80/artifact/

# Copy custom OVMF
COPY staging/tdx/OVMF.inteltdx.fd /opt/fortanix/enclave-os/blobs/OVMF.inteltdx.fd

# Copy gpu disabled artifacts
COPY staging/kernel_disabled_gpu/init /opt/fortanix/enclave-os/blobs/kernel_disabled_gpu/init
COPY staging/tdx/kernel_disabled_gpu/.config /opt/fortanix/enclave-os/blobs/kernel_disabled_gpu/bzImage.config
COPY staging/tdx/kernel_disabled_gpu/bzImage /opt/fortanix/enclave-os/blobs/kernel_disabled_gpu/bzImage

# Copy gpu enabled artifacts
COPY staging/kernel_enabled_gpu/init /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/init
COPY staging/tdx/kernel_enabled_gpu/.config /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/bzImage.config
COPY staging/tdx/kernel_enabled_gpu/bzImage /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/bzImage
COPY staging/tdx/kernel_enabled_gpu/nvidia-uvm.ko /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/nvidia-uvm.ko
COPY staging/tdx/kernel_enabled_gpu/nvidia.ko /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/nvidia.ko
COPY staging/tdx/kernel_enabled_gpu/nvidia-drm.ko /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/nvidia-drm.ko
COPY staging/tdx/kernel_enabled_gpu/nvidia-modeset.ko /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/nvidia-modeset.ko

# Copy the parts that change often last to reuse layers
COPY staging/server staging/parent-base.tar staging/enclave-base.tar staging/enclave-base-gpu.tar /app/

ENTRYPOINT [ "./server" ]
