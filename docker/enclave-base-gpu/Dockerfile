# Image placed inside a SEV-SNP confidential VM with GPU passthrough.
# The NVIDIA kernel modules are shipped with the guest kernel (either
# built-in or paired as pre-built .ko files separately). This image
# carries only the userspace NVIDIA driver (libcuda, nvidia-smi,
# libnvidia-ml) that applications and tooling use to talk to them.
FROM alpine:3.24 AS enclave-base-gpu

RUN apk update && apk upgrade

#  Runtime packages. Groups:
#
#   Guest utilities shared with the Nitro enclave-base:
#     ca-certificates - TLS trust anchors for HTTPS inside the guest
#     cryptsetup      - opens LUKS-encrypted persistent volumes
#     nbd-client      - mounts the NBD-served disk from the host

RUN apk add --no-cache ca-certificates \
    && update-ca-certificates

# The options passed to umount are not supported by busybox umount
RUN apk add --no-cache cryptsetup mount nbd-client umount

COPY --from=common-build-context nvidia-artifacts.tar.gz /
RUN tar xpf /nvidia-artifacts.tar.gz -C /
# The musl loader searches paths declared in `ld-musl-x86_64.path`.
RUN printf '%s\n' /lib /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu > /etc/ld-musl-x86_64.path
RUN rm /nvidia-artifacts.tar.gz

# nvidia-smi tool is built against glibc, here we're explicitly
# installing glibc compatibility packages to satisfy the following
# nvidia-smi sanity check.
# After app container is mounted, the files from these package
# will be unused.
RUN apk add --no-cache gcompat libstdc++

# Fail-fast sanity checks. Catch kernel-module leakage from package manager
# dependencies, and verify the two artifacts the workload actually needs.
RUN if find /lib/modules -name 'nvidia*.ko*' 2>/dev/null | grep -q .; then \
        echo "ERROR: NVIDIA kernel modules unexpectedly present in image"; \
        exit 1; \
    fi \
    && test -f /usr/lib/x86_64-linux-gnu/libcuda.so.1 \
    && nvidia-smi --help > /dev/null
