#!/bin/sh

cargo_build_flag=""
vsock_proxy_bin_folder=""

if [ "$1" = "release" ]; then
  cargo_build_flag="--release"
  vsock_proxy_bin_folder="release"
else
  vsock_proxy_bin_folder="debug"
fi;

cd vsock-proxy
cargo build $cargo_build_flag
cp "target/${vsock_proxy_bin_folder}/enclave" ../tools/container-converter/src/resources/enclave
cp "target/${vsock_proxy_bin_folder}/parent" ../tools/container-converter/src/resources/parent

cd ../tools/container-converter
cargo build $cargo_build_flag
