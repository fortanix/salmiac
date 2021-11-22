#!/bin/bash

set -exo pipefail

# This script may be run directly. It is also called from
# $repo_root/metering/ci.sh. build-utils takes care of
# handling both cases.

source "$(dirname ${BASH_SOURCE[0]})"/../tools/ci-scripts/build-utils.sh

if [ "$ROCHE_MODE" != "ci-sgx" -o "$RELEASE_OPT" != "--release" ]; then
    echo "Skipping docker build because config is not for release"
    eval $exit_or_return
fi

PRODUCT_BACKEND="nitro-converter"
PRODUCT_BACKEND_RUNNER="server"
PARENT_BASE_IMAGE="nitro-parent-base.tar"
# This is the directory where the dockerfile is stored
PRODUCT_DOCKER_BUILD_DIR="$(dirname ${BASH_SOURCE[0]})"

pushd "$PRODUCT_DOCKER_BUILD_DIR"
# build_docker_image will only do something for SGX release config
build_docker_image $PRODUCT_BACKEND${VERSION_SUFFIX} \
    $ARTIFACTS_DIR/$PRODUCT_BACKEND_RUNNER \
    $ARTIFACTS_DIR/$PARENT_BASE_IMAGE
popd
