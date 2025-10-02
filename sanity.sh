#! /bin/bash
# This script is meant to be sourced by other shell scripts to provide
# CI sanity checks.

set -exo pipefail

if [ -z "$repo_root" ] ; then
    repo_root=$(readlink -f "$(dirname "${BASH_SOURCE[0]}")")
fi

RUSTFMT_PATHS=(
    "$repo_root/api-model"
    "$repo_root/enclave-startup"
    "$repo_root/tools/container-converter"
    "$repo_root/vsock-proxy"
    "$repo_root/vsock-proxy/enclave"
    "$repo_root/vsock-proxy/shared"
    "$repo_root/vsock-proxy/parent"
    "$repo_root/vsock-proxy/parent/lib"
)

declare -A CLIPPY_PATHS=(
    [enclave_startup]="$repo_root/enclave-startup"
    [converter]="$repo_root/tools/container-converter"
    [vsock_proxy]="$repo_root/vsock-proxy"
)

for path_to_check in "${RUSTFMT_PATHS[@]}"
do
    pushd "$path_to_check"
    cargo fmt --check
#    TODO: RTE-568
#    cargo sort --check
    popd
done

# TODO: RTE-567
#for key in "${!CLIPPY_PATHS[@]}"
#do
#    pushd "${CLIPPY_PATHS[$key]}"
#    cargo clippy --no-deps --all-features -- -D warnings
#    popd
#done
