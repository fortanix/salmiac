FROM ubuntu as nitro-cli
ENV DEBIAN_FRONTEND=noninteractive

# Install packages for rust toolchain
RUN apt-get update && apt-get install -y apt-utils \
     curl  \
     sudo \
     git \
     make \
     gpg \
     gcc \
     llvm-dev \
     libclang-dev \
     clang \
     gnupg \
     lsb-release \
     libssl-dev \
     pkg-config \
     musl-tools

# Install rust toolchain and its dependencies
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Setup the right rust ver
ENV RUST_VERSION=1.49.0

RUN rustup toolchain install ${RUST_VERSION}-x86_64-unknown-linux-gnu
RUN rustup default ${RUST_VERSION}-x86_64-unknown-linux-gnu
RUN rustup target add --toolchain ${RUST_VERSION} x86_64-unknown-linux-musl

# Install nitro-cli
ENV NITRO_CLI_INSTALL_DIR=./install
RUN git clone https://github.com/aws/aws-nitro-enclaves-cli.git && \
    cd aws-nitro-enclaves-cli && \
    make nitro-cli-native && make vsock-proxy-native && make install

# Resulting image
FROM ubuntu as parent-base

# Minimum amount of utilities to run networking and nitro-cli
RUN apt-get update && apt-get install -y net-tools \
     iproute2 \
     curl  \
     iptables \
     jq \
     libpcap-dev \
     sudo \
     kmod \
     systemctl

# Copy nitro-cli files
COPY --from=nitro-cli aws-nitro-enclaves-cli/install/etc/nitro_enclaves /etc/nitro_enclaves
COPY --from=nitro-cli aws-nitro-enclaves-cli/install/etc/profile.d /etc/profile.d
COPY --from=nitro-cli aws-nitro-enclaves-cli/install/lib/modules /lib/modules
COPY --from=nitro-cli aws-nitro-enclaves-cli/install/usr/bin /usr/bin
COPY --from=nitro-cli aws-nitro-enclaves-cli/install/usr/lib/systemd/system /usr/lib/systemd/system
COPY --from=nitro-cli aws-nitro-enclaves-cli/install/usr/share /usr/share

# Setup the env for nitro-cli
RUN mkdir -p /var/log/nitro_enclaves
