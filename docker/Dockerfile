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

COPY staging/server /app
COPY staging/nitro-parent-base.tar /

ENTRYPOINT [ "./server" ]