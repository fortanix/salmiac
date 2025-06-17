#!/bin/bash

set -exo pipefail

# Run unit tests
if [ $FLAVOR == "release" ]; then
  cargo_build_flag="--release"
fi;

if [ -z "$SKIP_RUNNING_TESTS" ]; then
  if [ -z "$FORTANIX_API_KEY" ]; then
      echo "Environment variable FORTANIX_API_KEY is unset. Unable to run dsm_key_config unit tests"
      exit 1
  fi
  unit_test_dirs=(
      "vsock-proxy/enclave"
      "vsock-proxy/parent"
      "tools/container-converter"
  )
for unit_test_dir in "${unit_test_dirs[@]}"
  do
    pushd "$unit_test_dir"
    cargo test $cargo_build_flag --locked
    popd
  done
fi

pushd api-model
  cargo test $cargo_build_flag --features=serde --locked
popd
