FROM rust:1.53.0 as build
RUN apt-get update && \
    apt-get install -y libpcap-dev make

ADD vsock-proxy /opt/salmiac/vsock-proxy
ADD tools/container-converter /opt/salmiac/tools/container-converter

WORKDIR /opt/salmiac

RUN cd vsock-proxy && \
    cat Cargo.toml && \
    cargo build

RUN cd tools/container-converter && \
    cat Cargo.toml && \
    cat Makefile && \
    /usr/bin/make

FROM ubuntu-networking

COPY --from=build /opt/target/debug/vsock-proxy .
COPY startup.sh .

CMD ./startup.sh

