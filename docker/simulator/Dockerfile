FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        cryptsetup-bin \
        sudo \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/enclave-os /opt/fortanix/enclave-os/blobs

WORKDIR /app

COPY staging/server staging/parent-base.tar staging/enclave-base.tar /app/

COPY staging/blobs/init /opt/fortanix/enclave-os/blobs/init
COPY staging/blobs/kernel /opt/fortanix/enclave-os/blobs/kernel

ENTRYPOINT [ "./server" ]
