#!/bin/bash

set -exo pipefail

get_image_tag() {
  local tagfile_path="$1"
  local tag=$(cat "${tagfile_path}")

  if [[ -n "${TAG_SUFFIX}" ]]; then
    echo "${tag}-${TAG_SUFFIX}"
  else
    echo $tag
  fi
}

project_root="$(realpath "$(dirname "${BASH_SOURCE[0]}")/..")"
artifacts_dir="${project_root}/artifacts"

mkdir -p "${artifacts_dir}/${SALMIAC_PLATFORM}"
images_file="${artifacts_dir}/docker_images"
rm -f $images_file

pushd docker
export ENCLAVE_TAG=$(get_image_tag enclave-base/tag)
export ENCLAVE_IMAGE="${ENCLAVE_IMAGE:-enclave-base}:${ENCLAVE_TAG}"
docker build --no-cache -t "${ENCLAVE_IMAGE}" ./enclave-base
echo $ENCLAVE_IMAGE >> $images_file

case "$SALMIAC_PLATFORM" in
  nitro)
    export PARENT_TAG=$(get_image_tag nitro/parent-base/tag)
    export PARENT_IMAGE="${PARENT_IMAGE:-parent-base-nitro}:${PARENT_TAG}"
    docker build --no-cache --build-context common-build-context=./common-build-context -t $PARENT_IMAGE nitro/parent-base/
    echo $PARENT_IMAGE >> $images_file
    popd
    ;;
  snp | tdx | simulator)
    export PARENT_TAG=$(get_image_tag qemu/parent-base/tag)
    export PARENT_IMAGE="${PARENT_IMAGE:-parent-base-${SALMIAC_PLATFORM}}:${PARENT_TAG}"
    echo $PARENT_IMAGE >> $images_file
    docker build --no-cache qemu/parent-base --build-context common-build-context=./common-build-context -t $PARENT_IMAGE
    
    if [[ "${SKIP_ENCLAVE_BASE_GPU}" != "true" ]]; then
      export ENCLAVE_GPU_TAG=$(get_image_tag enclave-base-gpu/tag)
      export ENCLAVE_GPU_IMAGE="${ENCLAVE_GPU_IMAGE:-enclave-base-gpu}:${ENCLAVE_GPU_TAG}"
      cp -a "staging/${SALMIAC_PLATFORM}/kernel_enabled_gpu/nvidia-artifacts.tar.gz" common-build-context/.
      docker build --no-cache enclave-base-gpu --build-context common-build-context=./common-build-context -t $ENCLAVE_GPU_IMAGE
      echo $ENCLAVE_GPU_IMAGE >> $images_file
      popd
      docker save $ENCLAVE_GPU_IMAGE -o "${artifacts_dir}/${SALMIAC_PLATFORM}/enclave-base-gpu.tar"
    else
      popd
    fi
    ;;
esac

docker save $ENCLAVE_IMAGE -o "${artifacts_dir}/enclave-base.tar"
docker save $PARENT_IMAGE -o "${artifacts_dir}/${SALMIAC_PLATFORM}/parent-base.tar"