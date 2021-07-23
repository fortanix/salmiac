FROM fnndsc/ubuntu-python3
RUN apt-get update && \
 apt-get install -y net-tools iproute2 netcat dnsutils curl iputils-ping iptables nmap tcpdump uml-utilities libpcap-dev
COPY index.html web-server.py ./
CMD ./web-server.py