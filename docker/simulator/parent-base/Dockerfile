FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl  \
        dnsmasq \
        iproute2 \
        iptables \
        jq \
        kmod \
        libpcap-dev \
        nbd-server \
        net-tools \
        qemu-system-x86 \
        strace \
        sudo \
        systemctl \
        tcpdump \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /
