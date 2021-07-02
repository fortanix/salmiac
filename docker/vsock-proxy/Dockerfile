FROM rust:1.53.0 as build
RUN apt-get update && \
    apt-get install -y libpcap-dev
ADD vsock-proxy /opt/
WORKDIR /opt/
RUN cat Cargo.toml
RUN cargo build

FROM ubuntu-networking

COPY --from=build /opt/target/debug/vsock-proxy .
COPY startup.sh .

CMD ./startup.sh

