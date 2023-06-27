# This is a minimum development image that can run networking inside an enclave.

FROM ubuntu as ubuntu-networking
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y net-tools \
    iproute2 \
    netcat \
    dnsutils \
    curl \
    iputils-ping \
    iptables \
    nmap \
    tcpdump \
    uml-utilities
