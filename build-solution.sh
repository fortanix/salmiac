#!/bin/bash

set -exo pipefail

SALMIAC_PLATFORMS=(
    nitro
    snp
    tdx
    simulator
)

# Build converters
for platform in "${SALMIAC_PLATFORMS[@]}"
do
    SALMIAC_PLATFORM="${platform}" SKIP_ENCLAVE_BASE_GPU=true ./build-converter.sh
done
