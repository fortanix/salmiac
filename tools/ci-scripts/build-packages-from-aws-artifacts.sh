#!/bin/bash

# Usage: build-package-from-aws-artifacts --version <x.y.z> --release

set -exo pipefail

source "$(dirname ${BASH_SOURCE[0]})"/build-utils.sh

# Note that this will remove everything from $ARTIFACTS_DIR other than what it
# downloads.
data_files="docker_image_list.txt"
exec_files="server"
download_artifacts_for_packaging --data-files="${data_files}" --exec-files="${exec_files}"

source "$repo_root"/salmiac/docker/build.sh
