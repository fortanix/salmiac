{ [ -n "${__SALMIAC_TOOLS_BUILD_UTILS__:-}" ] && return; } || readonly __SALMIAC_TOOLS_BUILD_UTILS__=1

# Common build helpers
#
# Source this script from your build script.
#
# To support running build scripts for individual components, this script
# checks if it is invoked by the top-level build script. If it is, then
# it parses arguments, sets repo_root, and defines the helper functions.
# If it is not invoked by the top-level build script, it does nothing.

repo_root=$(readlink -f $(dirname "${BASH_SOURCE[0]}")/../../..)
if [ -z "${DOCKER_REGISTRY}" ]; then
    export DOCKER_REGISTRY="513076507034.dkr.ecr.us-west-1.amazonaws.com"
fi

# Set default values
RELEASE_OPT=--debug
ROCHE_MODE=ci-sgx
ENCLAVE_SIGNING_KEY="$repo_root"/salmiac/debug-enclave-signing.pem
# Note: This is base path for Metering artifacts. VERSION is also appended to this.
S3_BUCKET_ARTIFACTS_PATH="s3://fortanix-jenkins-artifacts/salmiac"

# TODO: checkout-toolchain should probably move to ci.sh, to ensure it only happens once
source "${repo_root}/tools/toolchain/jenkins-checkout-toolchain"
source "${repo_root}/tools/toolchain/tool-versions"
"${repo_root}/tools/build-container/update-build-container.sh" ci
source "${repo_root}/tools/utils.sh"
source "${repo_root}/tools/build-utils.sh"

# parse_arguments can set or modify the RELEASE_OPT, ROCHE_MODE, ENCLAVE_SIGNING_KEY, VERSION, 
# FORTANIX_BUILD_NUMBER, PRODUCTION
parse_arguments "$@"
# This is needed so that subsequent scripts don't see the arguments passed to ci anymore
shift $#

config_check

# it sets or modifies the ELF2SGXS_OPTS, RUST_HOST_TARGET_DIR, RUST_TARGET_DIR, CARGO_OPTS,
# VERSION_SUFFIX
set_vars_based_on_release_opt

ARTIFACTS_DIR="$repo_root/salmiac/artifacts"
mkdir -p $ARTIFACTS_DIR

pushd "$repo_root"/salmiac/product-version
cargo build --locked $CARGO_OPTS
popd

PRODUCT_VERSION=$("${repo_root}"/salmiac/product-version/${RUST_HOST_TARGET_DIR}/salmiac-product-version)

echo "$PRODUCT_VERSION" > "$ARTIFACTS_DIR/version.txt"
