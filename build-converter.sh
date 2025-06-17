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

pushd tools/container-converter
cargo build $cargo_build_flag $features_list --locked

popd
