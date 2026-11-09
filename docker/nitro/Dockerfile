FROM fortanix/parent-base-nitro:4.1.0 as nitro-cli

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get upgrade -y -o Acquire::Retries=0 \
    && apt-get install -y \
            cryptsetup-bin \
            sudo \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists

# Copy nitro-cli files
COPY --from=nitro-cli /etc/nitro_enclaves /etc/nitro_enclaves
COPY --from=nitro-cli /usr/bin/nitro-cli /usr/bin
COPY --from=nitro-cli /usr/bin/nitro-enclaves-allocator /usr/bin

RUN mkdir -p /var/log/nitro_enclaves

WORKDIR /app

COPY staging/server staging/parent-base.tar staging/enclave-base.tar /app/

# amzn-linux-nbd directory is available in the project root directory
# when ci.sh is run. ci.sh is responsible for fetching amzn-linux-nbd
# artifact from the fortanix S3
COPY x86_64/bzImage.config /usr/share/nitro_enclaves/blobs/bzImage.config
COPY x86_64/bzImage /usr/share/nitro_enclaves/blobs/bzImage
COPY x86_64/cmdline /usr/share/nitro_enclaves/blobs/cmdline
COPY --chmod=u=rwx,go=rx x86_64/init /usr/share/nitro_enclaves/blobs/init
COPY --chmod=u=rwx,go=rx x86_64/linuxkit /usr/share/nitro_enclaves/blobs/linuxkit
COPY x86_64/nsm.ko /usr/share/nitro_enclaves/blobs/nsm.ko

ENTRYPOINT [ "./server" ]
