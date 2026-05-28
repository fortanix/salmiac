# This Dockerfile describes an image that is placed inside an enclave.
# It contains the minimum possible amount of tools needed to produce a working environment for a client application.
# The size of this image should be kept as small as possible to minimize the amount of RAM needed for the enclave to run.
#
# This image is backend-agnostic and is used for both AWS Nitro Enclaves
# and SEV-SNP confidential VMs without GPU passthrough. The SEV-SNP path
# with GPU passthrough uses docker/enclave-base-snp-gpu/ instead, which
# adds the userspace NVIDIA driver bits.

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
        ca-certificates \
        cryptsetup \
        nbd-client \
        openssl
RUN apt-get clean && rm -rf /var/lib/apt/lists
