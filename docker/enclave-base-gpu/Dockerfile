# Image placed inside a SEV-SNP confidential VM with GPU passthrough.
# The NVIDIA kernel modules are shipped with the guest kernel (either
# built-in or paired as pre-built .ko files separately). This image
# carries only the userspace NVIDIA driver (libcuda, nvidia-smi,
# libnvidia-ml) that applications and tooling use to talk to them.

#TODO: RTE-944 Userspace hardening
ARG UBUNTU_VERSION=24.04

FROM ubuntu:${UBUNTU_VERSION} AS enclave-base-gpu
ARG NVIDIA_DRIVER_BRANCH=595
ARG NVIDIA_DRIVER_BRANCH_PINNED=595.71.05-0ubuntu0.24.04.1
ARG UBUNTU_SNAPSHOT=20260601T000000Z
ENV DEBIAN_FRONTEND=noninteractive

# Restrict Ubuntu repositories used by the snapshot:
#   disabled components: noble-backports
RUN sed -i \
        -e 's/ noble-backports//g' \
        /etc/apt/sources.list.d/ubuntu.sources

# Bootstrap HTTPS trust using the current archive first.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates

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
# Ubuntu security updates may publish newer NVIDIA libraries and firmware.
# Because the NVIDIA driver is supplied as a build artifact and requires specific
# older versions, use a repository snapshot to install the compatible packages.
RUN apt-get install \
        --update \
        --snapshot "${UBUNTU_SNAPSHOT}" \
        -y --no-install-recommends \
        ca-certificates \
        cryptsetup \
        nbd-client \
        libnvidia-compute-${NVIDIA_DRIVER_BRANCH}=${NVIDIA_DRIVER_BRANCH_PINNED} \
        nvidia-utils-${NVIDIA_DRIVER_BRANCH}=${NVIDIA_DRIVER_BRANCH_PINNED} \
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
