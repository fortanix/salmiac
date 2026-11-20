# This Dockerfile describes an image that is placed inside an enclave.
# It contains the minimum possible amount of tools needed to produce a working environment for a client application.
# The size of this image should be kept as small as possible to minimize the amount of RAM needed for the enclave to run.
#
# This image is backend-agnostic and is used for AWS Nitro Enclaves, SEV-SNP
# confidential VMs and TDX confidential VMs without GPU passthrough. The SEV-SNP and TDX paths
# with GPU passthrough uses docker/enclave-base-gpu/ instead, which
# adds the userspace NVIDIA driver bits.
FROM alpine:edge

RUN apk add --no-cache ca-certificates \
    && apk upgrade --no-cache ca-certificates ca-certificates-bundle \
    && update-ca-certificates

RUN apk info -V ca-certificates ca-certificates-bundle

# The options passed to umount are not supported by busybox umount
RUN apk add --no-cache cryptsetup mount umount
