#!/bin/bash

set -exo pipefail

cargo_build_flag=""
vsock_proxy_bin_folder=""
enclave_startup_bin_folder=""
# Enclave startup is statically linked to musl instead of glibc
# to avoid problems runtime linking errors with libnss SALM-345
enclave_startup_toolchain="x86_64-unknown-linux-musl"

if [ $FLAVOR == "release" ]; then
  cargo_build_flag="--release"
  vsock_proxy_bin_folder="release"
  enclave_startup_bin_folder="$enclave_startup_toolchain/release"
else
  vsock_proxy_bin_folder="debug"
  enclave_startup_bin_folder="$enclave_startup_toolchain/debug"
fi;

features_list=""
if [ ! -z "$2" ]; then
  features_list="--features "$2
fi;

pushd "${SALMIAC_ROOT}/salmiac-runner/docker"
pushd ./enclave-base
export ENCLAVE_TAG=$(cat ./tag)
export ENCLAVE_IMAGE="${ENCLAVE_IMAGE:-encalve-base}:${ENCLAVE_TAG}"
docker build --no-cache -t "${ENCLAVE_IMAGE}" .
popd
docker save $ENCLAVE_IMAGE -o "${ARTIFACTS_DIR}/enclave-base.tar"

case "$SALMIAC_PLATFORM" in
  nitro)
    export PARENT_TAG=$(cat nitro/parent-base/tag)
    export PARENT_IMAGE="${PARENT_IMAGE:-parent-base-nitro}:${PARENT_TAG}"
    docker build --no-cache --build-context common-build-context=./common-build-context -t $PARENT_IMAGE nitro/parent-base/
    popd
    docker save $PARENT_IMAGE -o "${ARTIFACTS_DIR}/${SALMIAC_PLATFORM}/parent-base.tar"
    ;;
  snp | tdx)
    export PARENT_TAG=$(cat qemu/tag)
    export PARENT_IMAGE="${PARENT_IMAGE:-parent-base-${SALMIAC_PLATFORM}}:${PARENT_TAG}"
    export ENCLAVE_GPU_TAG=$(cat enclave-base-gpu/tag)
    export ENCLAVE_GPU_IMAGE="${ENCLAVE_GPU_IMAGE:-enclave-base-gpu}:${ENCLAVE_GPU_TAG}"
    cp -a "staging/${SALMIAC_PLATFORM}/kernel_enabled_gpu/nvidia-artifacts.tar.gz" common-build-context/.
    docker build --no-cache enclave-base-gpu --build-context common-build-context=./common-build-context -t $ENCLAVE_GPU_IMAGE
    docker build --no-cache qemu/parent-base --build-context common-build-context=./common-build-context -t $PARENT_IMAGE
    popd
    docker save $PARENT_IMAGE -o "${ARTIFACTS_DIR}/${SALMIAC_PLATFORM}/parent-base.tar"
    docker save $ENCLAVE_GPU_IMAGE -o "${ARTIFACTS_DIR}/${SALMIAC_PLATFORM}/enclave-base-gpu.tar"
    ;;
esac

pushd tools/container-converter
cargo build $cargo_build_flag $features_list --locked
popd