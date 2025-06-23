# This Dockerfile uses a Docker multi-stage build to create a temporary
# container for building the nitro tooling and then copy the compiled
# tools into a final container (which does not need to include the
# rust compiler and other build-related tools). The first part of the
# Dockerfile creates the temporary container.

FROM ubuntu:24.04 as nitro-cli
ENV DEBIAN_FRONTEND=noninteractive
# Install packages for rust toolchain
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y \
        apt-utils \
        clang \
        curl  \
        gcc \
        git \
        gnupg \
        gpg \
        libclang-dev \
        libssl-dev \
        llvm-dev \
        lsb-release \
        make \
        musl-tools \
        pkg-config \
        sudo

# Install rust toolchain and its dependencies
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
# Setup the right rust ver
ENV RUST_VERSION=1.71.1
RUN rustup toolchain install ${RUST_VERSION}-x86_64-unknown-linux-gnu
RUN rustup default ${RUST_VERSION}-x86_64-unknown-linux-gnu
RUN rustup target add --toolchain ${RUST_VERSION} x86_64-unknown-linux-musl
# Install nitro-cli. Use vendored version of openssl since various crates use openssl-sys 0.9 which
# works only with openssl1. RTE-386
ENV NITRO_CLI_INSTALL_DIR=./install
RUN git clone https://github.com/aws/aws-nitro-enclaves-cli.git && \
    cd aws-nitro-enclaves-cli && \
    git checkout v1.4.2 && \
    make nitro-cli-native && make vsock-proxy-native && make install-tools

# Final image build.
FROM ubuntu:24.04 as parent-base
# Minimum amount of utilities to run networking and nitro-cli.
# We also perform an apt-get upgrade to make sure we get the latest
# versions of all installed packages at the time the image is built.
# We do this primarily to pick up security fixes.
RUN apt-get update \
    && apt-get install -y \
        curl  \
        dnsmasq \
        iproute2 \
        iptables \
        jq \
        kmod \
        libpcap-dev \
        nbd-server \
        net-tools \
        sudo \
        systemctl \
        strace \
        tcpdump \
    && apt-get upgrade -y

# Copy nitro-cli files
COPY --from=nitro-cli aws-nitro-enclaves-cli/install/etc/nitro_enclaves /etc/nitro_enclaves
COPY --from=nitro-cli aws-nitro-enclaves-cli/install/usr/bin /usr/bin
COPY --from=nitro-cli aws-nitro-enclaves-cli/install/usr/lib/systemd/system /usr/lib/systemd/system
COPY --from=nitro-cli aws-nitro-enclaves-cli/install/usr/share /usr/share
COPY --from=nitro-cli aws-nitro-enclaves-cli/blobs/x86_64 /usr/share/nitro_enclaves/blobs

COPY dnsmasq.d /etc/dnsmasq.d
# Setup the env for nitro-cli
RUN mkdir -p /var/log/nitro_enclaves
