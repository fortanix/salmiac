FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        bash \
        busybox-static \
        ca-certificates \
        coreutils \
        cryptsetup \
        cryptsetup-bin \
        file \
        findutils \
        gdb \
        grep \
        iproute2 \
        kmod \
        nbd-client \
        procps \
        sed \
        strace \
        util-linux \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
