FROM 513076507034.dkr.ecr.us-west-1.amazonaws.com/nitro-parent-base:1.0.0 as nitro-cli

FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y libssl1.1

COPY --from=nitro-cli /usr/bin/nitro-cli /usr/bin/
COPY --from=nitro-cli /usr/share/nitro_enclaves/ /usr/share/

# Copy nitro-cli files
COPY --from=nitro-cli /etc/nitro_enclaves /etc/nitro_enclaves
COPY --from=nitro-cli /etc/profile.d /etc/profile.d
COPY --from=nitro-cli /lib/modules /lib/modules
COPY --from=nitro-cli /usr/bin/nitro-cli /usr/bin
COPY --from=nitro-cli /usr/bin/nitro-enclaves-allocator /usr/bin
COPY --from=nitro-cli /usr/share/nitro_enclaves /usr/share/nitro_enclaves

RUN mkdir -p /var/log/nitro_enclaves

WORKDIR /app

COPY staging/server staging/nitro-parent-base.tar staging/nitro-enclave-base.tar /app/

# amzn-linux-nbd directory is available in the project root directory
# when ci.sh is run. ci.sh is responsible for fetching amzn-linux-nbd
# artifact from the fortanix S3
# TODO: Enable the below once converter docker build is part of CI
# COPY amzn-linux-nbd/bzImage.config /usr/share/nitro_enclaves/blobs/bzImage.config
# COPY amzn-linux-nbd/bzImage /usr/share/nitro_enclaves/blobs/bzImage

ENTRYPOINT [ "./server" ]
