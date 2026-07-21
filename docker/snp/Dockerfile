# Download OVMF and EFI boot stubb
ARG NVIDIA_DRIVER_BRANCH=595

FROM ubuntu:25.10 AS apt_extract
RUN DEBIAN_FRONTEND=noninteractive apt-get update

RUN mkdir -p /blob

RUN apt-get download systemd-boot-efi \
    && dpkg -x systemd-boot-efi*.deb system_boot_efi_dir \
    && cp system_boot_efi_dir/usr/lib/systemd/boot/efi/linuxx64.efi.stub /blob

RUN apt-get download ovmf \
    && dpkg -x ovmf*.deb ovmf_dir \
    && cp ovmf_dir/usr/share/ovmf/OVMF.amdsev.fd /blob

FROM debian:bookworm-slim AS sev_snp_measurement
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y \
        python3 \
        python3-pip \
        git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY staging/sev-snp-measure/requirements.txt /tmp/requirements.txt
RUN pip install --break-system-packages --target /opt/sev-snp-dist -r /tmp/requirements.txt

FROM ubuntu:24.04 AS nvidia_userspace
ARG NVIDIA_DRIVER_BRANCH
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        libnvidia-compute-${NVIDIA_DRIVER_BRANCH} \
        nvidia-utils-${NVIDIA_DRIVER_BRANCH} \
        nvidia-kernel-common-${NVIDIA_DRIVER_BRANCH} \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists

COPY stage-nvidia-driver-payload.sh /usr/local/bin/stage-nvidia-driver-payload.sh
RUN bash -x /usr/local/bin/stage-nvidia-driver-payload.sh /nvidia-driver-payload

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y \
        cryptsetup-bin \
        python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists

COPY --from=sev_snp_measurement /opt/sev-snp-dist /opt/sev-snp-dist
ENV PYTHONPATH="/opt/sev-snp-dist"

COPY staging/sev-snp-measure /opt/sev-snp-measure
RUN chmod +x /opt/sev-snp-measure/measure.py

WORKDIR /app

COPY --from=apt_extract /blob /opt/fortanix/enclave-os/blobs
COPY --from=nvidia_userspace /nvidia-driver-payload /opt/fortanix/enclave-os/nvidia-driver-payload

# These need to be pulled in from Jenkins https://jenkins.fortanix.net/job/build-salmiac-kernel/80/artifact/

# Copy gpu disabled artifacts
COPY staging/kernel_disabled_gpu/init /opt/fortanix/enclave-os/blobs/kernel_disabled_gpu/init
COPY staging/snp/kernel_disabled_gpu/.config /opt/fortanix/enclave-os/blobs/kernel_disabled_gpu/bzImage.config
COPY staging/snp/kernel_disabled_gpu/bzImage /opt/fortanix/enclave-os/blobs/kernel_disabled_gpu/bzImage

# Copy gpu enabled artifacts
COPY staging/kernel_enabled_gpu/init /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/init
COPY staging/snp/kernel_enabled_gpu/.config /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/bzImage.config
COPY staging/snp/kernel_enabled_gpu/bzImage /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/bzImage
COPY staging/snp/kernel_enabled_gpu/nvidia-uvm.ko /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/nvidia-uvm.ko
COPY staging/snp/kernel_enabled_gpu/nvidia.ko /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/nvidia.ko
COPY staging/snp/kernel_enabled_gpu/nvidia-drm.ko /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/nvidia-drm.ko
COPY staging/snp/kernel_enabled_gpu/nvidia-modeset.ko /opt/fortanix/enclave-os/blobs/kernel_enabled_gpu/nvidia-modeset.ko

# Copy the parts that change often last to reuse layers
COPY staging/server staging/parent-base.tar staging/enclave-base.tar staging/enclave-base-gpu.tar /app/

ENTRYPOINT [ "./server" ]
