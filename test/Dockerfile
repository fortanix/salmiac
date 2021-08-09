FROM fnndsc/ubuntu-python3
RUN apt-get update && apt-get install -y curl \
    dnsutils \
    iproute2 \
    iptables \
    iputils-ping \
    libpcap-dev \
    net-tools \
    netcat \
    nmap \
    tcpdump \
    uml-utilities

COPY index.html web-server.py ./
CMD ./web-server.py