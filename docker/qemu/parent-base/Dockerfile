# Host-side toolbox image for launching SEV-SNP and TDX confidential VMs.
ARG UBUNTU_VERSION=24.04
ARG QEMU_VERSION=v10.2.2
ARG QEMU_TARBALL_SHA256=784b296ff29c1417aa72323abcb2d2ea9ab9771724f577dcd785c3b04f21e176

# Build QEMU from source at a pinned upstream release.
# Ubuntu 24.04 ships QEMU 8.2, which predates the mature SEV-SNP feature
# set we require. Downloading the release tarball and verifying its
# SHA-256 keeps behavior deterministic for attestation reference values
# and lets us upgrade deliberately.
FROM ubuntu:${UBUNTU_VERSION} AS qemu-builder
ARG QEMU_VERSION
ARG QEMU_TARBALL_SHA256
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        bison \
        build-essential \
        ca-certificates \
        curl \
        flex \
        git \
        libaio-dev \
        libcap-ng-dev \
        libglib2.0-dev \
        libpixman-1-dev \
        libseccomp-dev \
        libslirp-dev \
        meson \
        ninja-build \
        pkg-config \
        python3 \
        python3-venv \
        xz-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Download the official QEMU release tarball, verify its SHA-256, then
# extract. Any mismatch fails the build.
RUN QEMU_VER_NUM="${QEMU_VERSION#v}" \
    && curl -fsSL -o /tmp/qemu.tar.xz \
        "https://download.qemu.org/qemu-${QEMU_VER_NUM}.tar.xz" \
    && echo "${QEMU_TARBALL_SHA256}  /tmp/qemu.tar.xz" | sha256sum -c - \
    && mkdir -p /src/qemu \
    && tar -xJf /tmp/qemu.tar.xz -C /src/qemu --strip-components=1 \
    && rm /tmp/qemu.tar.xz

WORKDIR /src/qemu
RUN ./configure \
        --prefix=/opt/qemu \
        --target-list=x86_64-softmmu \
        --enable-kvm \
        --enable-slirp \
        --enable-seccomp \
        --disable-docs \
        --disable-gtk \
        --disable-sdl \
        --disable-vnc \
        --disable-werror \
    && make -j"$(nproc)" \
    && make install \
    && /opt/qemu/bin/qemu-system-x86_64 --version

# Final runtime image.
FROM ubuntu:${UBUNTU_VERSION} AS parent-base-qemu
ENV DEBIAN_FRONTEND=noninteractive

# Runtime packages. Groups:
#
#   QEMU runtime libraries, linked by the binaries built in stage 1:
#     libaio1t64      - libaio (async disk I/O)
#     libcap-ng0      - libcap-ng (POSIX capability drops for sandboxing)
#     libglib2.0-0t64 - GLib (QEMU's core utility library)
#     libpixman-1-0   - pixman (guest framebuffer pixel ops; still
#                       linked even with --disable-gtk/sdl/vnc)
#     libseccomp2     - seccomp BPF filter (--enable-seccomp)
#     libslirp0       - libslirp (user-mode networking, --enable-slirp)
#     zlib1g          - zlib (compressed disk images, bzImage loading)
#
#   Host <-> CVM networking for the fortanix-tap0 interface:
#     dnsmasq, iproute2, iptables, net-tools
#
#   Backing storage for the CVM's persistent disk (same as Nitro):
#     nbd-server
#
#   Linked by Salmiac's Rust networking crates (matches Nitro parent-base):
#     libpcap-dev
#
#   Kernel-module loader for KVM / VFIO setup on the host:
#     kmod
#
#   General userspace utilities used by Salmiac tooling:
#     ca-certificates, curl, jq, sudo, systemctl
#
#   Diagnostics:
#     strace, tcpdump
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dnsmasq \
        iproute2 \
        iptables \
        jq \
        kmod \
        libaio1t64 \
        libcap-ng0 \
        libglib2.0-0t64 \
        libpcap-dev \
        libpixman-1-0 \
        libseccomp2 \
        libslirp0 \
        nbd-server \
        net-tools \
        strace \
        sudo \
        systemctl \
        tcpdump \
        zlib1g \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists

# QEMU built above.
COPY --from=qemu-builder /opt/qemu /opt/qemu
ENV PATH="/opt/qemu/bin:${PATH}"

COPY --from=common-build-context dnsmasq.d /etc/dnsmasq.d

# Fail-fast sanity check.
RUN qemu-system-x86_64 --version
