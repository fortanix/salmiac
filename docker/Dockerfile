FROM fortanix/parent-base:1.2.0 as nitro-cli

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    cryptsetup-bin \
    sudo

# Copy nitro-cli files
COPY --from=nitro-cli /etc/nitro_enclaves /etc/nitro_enclaves
COPY --from=nitro-cli /usr/bin/nitro-cli /usr/bin
COPY --from=nitro-cli /usr/bin/nitro-enclaves-allocator /usr/bin
COPY --from=nitro-cli /usr/share/nitro_enclaves /usr/share/nitro_enclaves
COPY --from=nitro-cli /usr/bin/nitro-cli /usr/bin/
COPY --from=nitro-cli /usr/share/nitro_enclaves/ /usr/share/

RUN mkdir -p /var/log/nitro_enclaves

WORKDIR /app

COPY staging/server staging/nitro-parent-base.tar staging/nitro-enclave-base.tar /app/

# amzn-linux-nbd directory is available in the project root directory
# when ci.sh is run. ci.sh is responsible for fetching amzn-linux-nbd
# artifact from the fortanix S3
COPY amzn-linux-nbd/bzImage.config /usr/share/nitro_enclaves/blobs/bzImage.config
COPY amzn-linux-nbd/bzImage /usr/share/nitro_enclaves/blobs/bzImage

ENTRYPOINT [ "./server" ]
