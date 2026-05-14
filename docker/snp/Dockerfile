FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive


RUN mkdir -p /var/log/snp_enclaves

WORKDIR /app

COPY staging/server staging/parent-base.tar staging/enclave-base.tar staging/enclave-base-gpu.tar /app/

# TODO: update these paths according to latest location
COPY kernel_disabled_gpu/.config /usr/share/snp_enclaves/blobs/kernel_disabled_gpu/bzImage.config
COPY kernel_disabled_gpu/bzImage /usr/share/snp_enclaves/blobs/kernel_disabled_gpu/bzImage
COPY kernel_enabled_gpu/.config /usr/share/snp_enclaves/blobs/kernel_enabled_gpu/bzImage.config
COPY kernel_enabled_gpu/bzImage /usr/share/snp_enclaves/blobs/kernel_enabled_gpu/bzImage
COPY kernel_enabled_gpu/nvidia-uvm.ko /usr/share/snp_enclaves/blobs/kernel_enabled_gpu/nvidia-uvm.ko
COPY kernel_enabled_gpu/nvidia.ko /usr/share/snp_enclaves/kernel_enabled_gpu/nvidia.ko


ENTRYPOINT [ "./server" ]

