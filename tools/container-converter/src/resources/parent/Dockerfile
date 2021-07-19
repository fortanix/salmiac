# syntax=docker/dockerfile:1.2

# This is the foundational image that parent is built upon, it contains:
# - A minimum number of networking utilities
# - Rust toolchain
# - AWS Nitro tools to run and setup the enclaves

FROM ubuntu as packages
ENV DEBIAN_FRONTEND=noninteractive

# Install networking and common tools
RUN apt-get update && apt-get install -y apt-utils \
    tzdata \
     net-tools \
     iproute2 \
     netcat \
     dnsutils \
     curl  \
     iputils-ping \
     iptables \
     nmap \
     tcpdump \
     uml-utilities \
     sudo \
     kmod \
     nfs-common \
     systemctl \
     rpcbind \
     git \
     make \
     gpg \
     gcc \
     llvm-dev \
     libclang-dev \
     clang \
     apt-transport-https \
     ca-certificates \
     gnupg \
     lsb-release \
     jq \
     libpcap-dev

# Install rust toolchain and its dependencies
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install dependencies to be able to use musl target to produce statically
# linked binaries.
RUN apt-get install -y libssl-dev
RUN apt-get install -y pkg-config
RUN apt-get install -y musl-tools

# Setup the right rust ver
ENV RUST_VERSION=1.49.0

RUN rustup toolchain install ${RUST_VERSION}-x86_64-unknown-linux-gnu
RUN rustup default ${RUST_VERSION}-x86_64-unknown-linux-gnu
RUN rustup target add --toolchain ${RUST_VERSION} x86_64-unknown-linux-musl
RUN cargo install cargo-about --version 0.2.2

# Setup the env for nitro-cli
RUN mkdir -p /var/log/nitro_enclaves

# Install nitro-cli
FROM packages as parent-base
ENV NITRO_CLI_INSTALL_DIR=/
RUN git clone https://github.com/aws/aws-nitro-enclaves-cli.git && \
    cd aws-nitro-enclaves-cli && \
    make nitro-cli-native && make vsock-proxy-native && make install
