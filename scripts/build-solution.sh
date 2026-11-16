#!/bin/bash

set -eo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/inc.sh"

SALMIAC_PLATFORMS=(
    nitro
    snp
    tdx
    simulator
)

clanup() {
    "${scripts_dir}/build-vsock-proxy-musl.sh" --remove-cache
}

trap clanup EXIT

# Build converters
for platform in "${SALMIAC_PLATFORMS[@]}"
do
    # Build enclave-startup and vsock-proxy explicitly to provide clearer
    # error messages, even though container-converter also builds them.
    SALMIAC_PLATFORM="${platform}" "${scripts_dir}/build-enclave-startup-musl.sh"
    SALMIAC_PLATFORM="${platform}" "${scripts_dir}/build-vsock-proxy-musl.sh"
    SALMIAC_PLATFORM="${platform}" "${scripts_dir}/build-converter.sh"
done
