#!/bin/bash

set -exo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/inc.sh"

cargo_build_flag=""

if [ "${FLAVOR}" == "release" ]; then
  cargo_build_flag="--release"
fi;

features_list=""
if [ -n "$2" ]; then
  features_list="--features "$2
fi;

pushd "${repo_root}/tools/container-converter"
cargo build $cargo_build_flag "${features_list}" --locked
popd
