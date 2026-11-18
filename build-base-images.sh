#!/bin/bash

set -exo pipefail

project_root="$(realpath "$(dirname "${BASH_SOURCE[0]}")/..")"
artifacts_dir="${project_root}/artifacts"

pushd docker
export ENCLAVE_TAG=$(cat enclave-base/tag)
export ENCLAVE_IMAGE="${ENCLAVE_IMAGE:-enclave-base}:${ENCLAVE_TAG}"
docker build --no-cache -t "${ENCLAVE_IMAGE}" ./enclave-base

mkdir -p "${artifacts_dir}/${SALMIAC_PLATFORM}"

case "$SALMIAC_PLATFORM" in
  nitro)
    export PARENT_TAG=$(cat nitro/parent-base/tag)
    export PARENT_IMAGE="${PARENT_IMAGE:-parent-base-nitro}:${PARENT_TAG}"
    docker build --no-cache --build-context common-build-context=./common-build-context -t $PARENT_IMAGE nitro/parent-base/
    popd
    ;;
  snp | tdx | simulator)
    export PARENT_TAG=$(cat qemu/parent-base/tag)
    export PARENT_IMAGE="${PARENT_IMAGE:-parent-base-${SALMIAC_PLATFORM}}:${PARENT_TAG}"
    export ENCLAVE_GPU_TAG=$(cat enclave-base-gpu/tag)
    export ENCLAVE_GPU_IMAGE="${ENCLAVE_GPU_IMAGE:-enclave-base-gpu}:${ENCLAVE_GPU_TAG}"
    docker build --no-cache qemu/parent-base --build-context common-build-context=./common-build-context -t $PARENT_IMAGE
    
    if [[ "${SKIP_ENCLAVE_BASE_GPU}" != "true" ]]; then
      cp -a "staging/${SALMIAC_PLATFORM}/kernel_enabled_gpu/nvidia-artifacts.tar.gz" common-build-context/.
      docker build --no-cache enclave-base-gpu --build-context common-build-context=./common-build-context -t $ENCLAVE_GPU_IMAGE
      popd
      docker save $ENCLAVE_GPU_IMAGE -o "${artifacts_dir}/${SALMIAC_PLATFORM}/enclave-base-gpu.tar"
    else
      popd
    fi
    ;;
esac

docker save $ENCLAVE_IMAGE -o "${artifacts_dir}/enclave-base.tar"
docker save $PARENT_IMAGE -o "${artifacts_dir}/${SALMIAC_PLATFORM}/parent-base.tar"