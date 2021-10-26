FROM rust:1.53.0 as build
RUN apt-get update && \
    apt-get install -y libpcap-dev

ADD vsock-proxy /opt/salmiac/vsock-proxy
ADD tools/container-converter /opt/salmiac/tools/container-converter
ADD build-solution.sh /opt/salmiac/

WORKDIR /opt/salmiac

ARG RELEASE=debug
RUN bash -x ./build-solution.sh $RELEASE

FROM ubuntu-networking

COPY --from=build /opt/target/debug/vsock-proxy .
COPY startup.sh .

CMD ./startup.sh

