#!/usr/bin/env bash
set -e

script_dir=$(dirname "$(realpath "${BASH_SOURCE[0]})")")

salmiac_dir="${script_dir}"

if [ -n "${EMBED_ATTEST_CLIENT_ROCHE_PATH}" ]; then
  roche_path="${EMBED_ATTEST_CLIENT_ROCHE_PATH}"
else
  # If not set, assume that salmiac is a submodule of roche (roche/salmiac/salmiac-runner)
  roche_path="${salmiac_dir}/../roche"
fi

echo "----- Cleaning Embedded Attestation Client -----"
pushd "${salmiac_dir}/embedded-attestation-client" >/dev/null || exit

cargo clean -p "embedded-attestation-client"

popd > /dev/null || exit

echo "----- Cleaning Vsock Proxy -----"
pushd "${salmiac_dir}/vsock-proxy" >/dev/null || exit

cargo clean -p "enclave" -p "parent" -p "parent_lib" -p "shared" -p "embedded-attestation-client"

popd > /dev/null || exit

echo "----- Building Container Converter executable -----"
pushd "${salmiac_dir}/tools/container-converter" >/dev/null || exit

#SALMIAC_PLATFORM="snp" \
#EMBED_ATTEST_CLIENT_ROCHE_PATH="${roche_path}" \
#cargo build --release

# Debug build of the converter binary
SALMIAC_PLATFORM="snp" \
EMBED_ATTEST_CLIENT_ROCHE_PATH="${roche_path}" \
cargo build

if [ "${?}" -ne 0 ]; then
  echo "Container Converter executable build failed"
  exit 1
fi

popd > /dev/null || exit

build_flags="--no-cache"

#echo "----- Building Nitro parent-base -----"
#pushd "${salmiac_dir}/docker/nitro/parent-base" >/dev/null || exit
#docker build ${build_flags:+} -t "parent-base" .
#popd > /dev/null || exit

echo "----- Building enclave-base -----"
pushd "${salmiac_dir}/docker/enclave-base" >/dev/null || exit
docker build ${build_flags} -t "enclave-base" .
popd >/dev/null || exit

echo "----- Building enclave-base-gpu -----"
pushd "${salmiac_dir}/docker/snp/enclave-base-gpu" >/dev/null || exit
docker build ${build_flags} -t "enclave-base-snp-gpu" .
popd >/dev/null || exit

echo "----- Building parent-base-snp -----"
pushd "${salmiac_dir}/docker/qemu/parent-base" >/dev/null || exit
docker build --build-context "parent-base=${salmiac_dir}/docker/nitro/parent-base" ${build_flags} -t "parent-base" .
docker tag "parent-base" "parent-base-snp"
popd >/dev/null || exit

echo "----- Building Container Converter Docker image -----"
pushd "${salmiac_dir}/docker/snp" >/dev/null || exit
bash -x build-conv-container.sh debug
popd >/dev/null || exit

exit