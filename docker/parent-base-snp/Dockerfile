# Host-side toolbox image for launching SEV-SNP confidential VMs.
ARG UBUNTU_VERSION=24.04
ARG QEMU_VERSION=v10.2.2

# Build QEMU from source at a pinned tag.
# Ubuntu 24.04 ships QEMU 8.2, which predates the mature SEV-SNP feature set
# we require. Building from an upstream tag keeps behavior deterministic for
# attestation reference values and lets us upgrade deliberately.
FROM ubuntu:${UBUNTU_VERSION} AS qemu-builder
ARG QEMU_VERSION
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bison \
        build-essential \
        ca-certificates \
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
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${QEMU_VERSION}" \
        https://gitlab.com/qemu-project/qemu.git /src/qemu

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
FROM ubuntu:${UBUNTU_VERSION} AS parent-base-snp
ENV DEBIAN_FRONTEND=noninteractive

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

# QEMU built above.
COPY --from=qemu-builder /opt/qemu /opt/qemu
ENV PATH="/opt/qemu/bin:${PATH}"

COPY dnsmasq.d /etc/dnsmasq.d

# Fail-fast sanity check.
RUN qemu-system-x86_64 --version
