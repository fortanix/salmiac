# Image placed inside a SEV-SNP confidential VM with GPU passthrough.
# The NVIDIA kernel modules are shipped with the guest kernel (either
# built-in or paired as pre-built .ko files separately). This image
# carries only the userspace NVIDIA driver (libcuda, nvidia-smi,
# libnvidia-ml) that applications and tooling use to talk to them.

#TODO: RTE-944 Userspace hardening

ARG UBUNTU_VERSION=24.04
ARG NVIDIA_DRIVER_BRANCH=595

FROM ubuntu:${UBUNTU_VERSION} AS enclave-base-gpu
ARG NVIDIA_DRIVER_BRANCH
ENV DEBIAN_FRONTEND=noninteractive

# Runtime packages. Groups:
#
#   Guest utilities shared with the Nitro enclave-base:
#     ca-certificates - TLS trust anchors for HTTPS inside the guest
#     cryptsetup      - opens LUKS-encrypted persistent volumes
#     nbd-client      - mounts the NBD-served disk from the host
#
#   NVIDIA userspace driver (matches the guest kernel module version;
#   kernel-side is not installed from apt here):
#     libnvidia-compute-${NVIDIA_DRIVER_BRANCH}
#                     - libcuda.so.1, libnvidia-opencl.so.1,
#                       libnvidia-ptxjitcompiler.so.1
#     nvidia-utils-${NVIDIA_DRIVER_BRANCH}
#                     - nvidia-smi, libnvidia-ml.so.1, libnvidia-cfg.so.1
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        cryptsetup \
        nbd-client \
        libnvidia-compute-${NVIDIA_DRIVER_BRANCH} \
        nvidia-utils-${NVIDIA_DRIVER_BRANCH} \
        openssl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Fail-fast sanity checks. Catch kernel-module leakage from apt
# dependencies, and verify the two artifacts the workload actually needs.
RUN if find /lib/modules -name 'nvidia*.ko*' 2>/dev/null | grep -q .; then \
        echo "ERROR: NVIDIA kernel modules unexpectedly present in image"; \
        exit 1; \
    fi \
    && test -f /usr/lib/x86_64-linux-gnu/libcuda.so.1 \
    && nvidia-smi --help > /dev/null
