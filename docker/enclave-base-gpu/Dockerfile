# Image placed inside a SEV-SNP confidential VM with GPU passthrough.
# The NVIDIA kernel modules are shipped with the guest kernel (either
# built-in or paired as pre-built .ko files separately). This image
# carries only the userspace NVIDIA driver (libcuda, nvidia-smi,
# libnvidia-ml) that applications and tooling use to talk to them.
FROM alpine:20260805

RUN apk add --no-cache ca-certificates \
    && apk upgrade --no-cache ca-certificates ca-certificates-bundle \
    && update-ca-certificates

RUN apk info -V ca-certificates ca-certificates-bundle

# The options passed to umount are not supported by busybox umount
RUN apk add --no-cache cryptsetup mount umount

COPY --from=common-build-context nvidia-artifacts.tar.gz /
RUN tar xpf /nvidia-artifacts.tar.gz -C /
RUN ldconfig
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
