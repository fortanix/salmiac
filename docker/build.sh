#!/bin/bash

set -exo pipefail

# This script may be run directly. It is also called from
# $repo_root/metering/ci.sh. build-utils takes care of
# handling both cases.

source "$(dirname ${BASH_SOURCE[0]})"/../tools/ci-scripts/build-utils.sh

PRODUCT_BACKEND="nitro-converter"
PRODUCT_BACKEND_RUNNER="server"
PARENT_BASE_IMAGE="parent-base.tar"
ENCLAVE_BASE_IMAGE="enclave-base.tar"
# This is the directory where the dockerfile is stored
PRODUCT_DOCKER_BUILD_DIR="$(dirname ${BASH_SOURCE[0]})"

pushd "$PRODUCT_DOCKER_BUILD_DIR"
# Run the script which fetches the modified enclave kernel from fortanix
# S3. This enclave kernel has the nbd & dm-crypt kernel module built into
# it, which allow us to have a persistant filesystem for nitro enclaves
source build-enclave-kernel.sh fetch

# build_docker_image will only do something for SGX release config
# build_docker_image() only builds the converter in release mode,
# this variable allows us to build the converter in debug mode as well
# and make the build part of PR jobs.
# It is not preferred to build salmiac in release mode in PR jobs
# since rust takes much longer to compile and build the project.
SALM_CONV_BUILD=true build_docker_image $PRODUCT_BACKEND \
    $ARTIFACTS_DIR/$PRODUCT_BACKEND_RUNNER \
    $ARTIFACTS_DIR/$PARENT_BASE_IMAGE \
    $ARTIFACTS_DIR/$ENCLAVE_BASE_IMAGE

source build-enclave-kernel.sh clean

popd
