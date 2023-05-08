#!/bin/bash

set -exo pipefail

cargo_build_flag=""
vsock_proxy_bin_folder=""
enclave_startup_bin_folder=""
# Enclave startup is statically linked to musl instead of glibc
# to avoid problems runtime linking errors with libnss SALM-345
enclave_startup_toolchain="x86_64-unknown-linux-musl"

if [ "$1" = "--release" ]; then
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

mkdir -p tools/container-converter/src/resources/enclave
mkdir -p tools/container-converter/src/resources/parent

pushd vsock-proxy
cargo build $cargo_build_flag $features_list

cp "target/${vsock_proxy_bin_folder}/enclave" ../tools/container-converter/src/resources/enclave
cp "target/${vsock_proxy_bin_folder}/parent" ../tools/container-converter/src/resources/parent

popd

pushd enclave-startup
rustup target add $enclave_startup_toolchain
cargo build $cargo_build_flag $features_list --target $enclave_startup_toolchain
file "target/$enclave_startup_bin_folder/enclave-startup"
cp "target/$enclave_startup_bin_folder/enclave-startup" ../tools/container-converter/src/resources/enclave

popd

pushd tools/container-converter
cargo build $cargo_build_flag $features_list

popd

pushd container-converter-service
cargo build $cargo_build_flag $features_list

popd
