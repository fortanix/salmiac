#!/bin/bash

set -exo pipefail

SALMIAC_PLATFORMS=(
    nitro
    snp
    tdx
)

# Run unit tests
if [ $FLAVOR == "release" ]; then
  cargo_build_flag="--release"
fi

if [ -z "$SKIP_RUNNING_TESTS" ]; then
  if [ -z "$FORTANIX_API_KEY" ]; then
      echo "Environment variable FORTANIX_API_KEY is unset. Unable to run dsm_key_config unit tests"
      exit 1
  fi
  # Platform agnostic tests
  pushd "tools/enclaveos-encrypted-fs"
    cargo test "$cargo_build_flag" --locked
  popd
  # Platform specific tests
  unit_test_dirs=(
      "vsock-proxy/enclave"
      "vsock-proxy/parent"
      "tools/container-converter"
  )
  for platform in "${SALMIAC_PLATFORMS[@]}"
  do
      for unit_test_dir in "${unit_test_dirs[@]}"
      do
          pushd "$unit_test_dir"
            SALMIAC_PLATFORM="${platform}" cargo test "$cargo_build_flag" --locked
          popd
      done
      pushd "api-model"
        SALMIAC_PLATFORM="${platform}" cargo test "$cargo_build_flag" --features=serde --locked
      popd
  done
fi

