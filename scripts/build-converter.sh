#!/bin/bash

set -eo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/inc.sh"

cargo_args=(--locked)

if [ "${FLAVOR}" == "release" ]; then
  cargo_args+=(--release)
fi;

if [ -n "$2" ]; then
  cargo_args+=(--features "${2}")
fi;

pushd "${repo_root}/tools/container-converter"
cargo build "${cargo_args[@]}"
popd
