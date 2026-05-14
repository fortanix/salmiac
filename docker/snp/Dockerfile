# Download OVMF and EFI boot stubb
FROM ubuntu:25.10 as apt_extract
RUN DEBIAN_FRONTEND=noninteractive apt-get update

RUN mkdir -p /blob

RUN apt-get download systemd-boot-efi && \
dpkg -x systemd-boot-efi*.deb system_boot_efi_dir &&\
cp system_boot_efi_dir/usr/lib/systemd/boot/efi/linuxx64.efi.stub /blob


RUN apt-get download ovmf && \
dpkg -x ovmf*.deb ovmf_dir && \
cp ovmf_dir/usr/share/ovmf/OVMF.amdsev.fd /blob

FROM ubuntu:24.04

RUN mkdir -p /var/log/snp_enclaves

WORKDIR /app

COPY staging/server staging/parent-base.tar staging/enclave-base.tar staging/enclave-base-gpu.tar /app/

COPY --from=apt_extract /blob /usr/share/snp_enclaves/blobs
COPY kernel_disabled_gpu/.config /usr/share/snp_enclaves/blobs/kernel_disabled_gpu/bzImage.config
COPY kernel_disabled_gpu/bzImage /usr/share/snp_enclaves/blobs/kernel_disabled_gpu/bzImage
COPY kernel_enabled_gpu/.config /usr/share/snp_enclaves/blobs/kernel_enabled_gpu/bzImage.config
COPY kernel_enabled_gpu/bzImage /usr/share/snp_enclaves/blobs/kernel_enabled_gpu/bzImage
COPY kernel_enabled_gpu/nvidia-uvm.ko /usr/share/snp_enclaves/blobs/kernel_enabled_gpu/nvidia-uvm.ko
COPY kernel_enabled_gpu/nvidia.ko /usr/share/snp_enclaves/blobs/kernel_enabled_gpu/nvidia.ko

ENTRYPOINT [ "./server" ]
