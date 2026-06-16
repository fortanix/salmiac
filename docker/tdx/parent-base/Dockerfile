# Host-side toolbox image for launching TDX confidential VMs.
ARG UBUNTU_VERSION=24.04
FROM ubuntu:${UBUNTU_VERSION}
ENV DEBIAN_FRONTEND=noninteractive
# We use TDX-enabled build of QEMU 8.2.2, patched by the Kobuk team
# on top of ubuntu:24.04 to support confidential VM workloads.
# Starting with Ubuntu 25.10, base TDX host support has been fully enabled directly in Ubuntu with no PPA required.
ARG QEMU_VERSION=2:8.2.2+ds-0ubuntu1.4+tdx1.1

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
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update  \
    && apt-get install -y --no-install-recommends gnupg \
    && echo "deb https://ppa.launchpadcontent.net/kobuk-team/tdx-release/ubuntu noble main" \
        > /etc/apt/sources.list.d/tdx.list \
    &&  curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x4D098D70AFBE5E1F" \
        | gpg --dearmor -o /etc/apt/trusted.gpg.d/kobuk-tdx.gpg \
    && apt-get update \
    && apt-get install -y  --no-install-recommends qemu-system-x86=${QEMU_VERSION} \
    && rm -rf /var/lib/apt/lists/*

COPY ./dnsmasq.d /etc/dnsmasq.d

# Fail-fast sanity check.
RUN qemu-system-x86_64 --version
