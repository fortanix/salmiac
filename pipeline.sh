#!/usr/bin/env bash

set -Eeuo pipefail

git submodule update --init
source tools/build-container/devops/tools/bitbucket-api/bitbucket-buildstatus.sh

testname="salmiac-pr"
description="Builds Salmiac project and runs tests"
link="${BUILD_URL}"

updateStatus () {
    result=$1
    echo "Updating status on commit ${commit_hash} to ${result}"
    BitBucketGetAccessToken "${bitbucket_key}" "${bitbucket_secret}"
	BitBucketSetStatus "${result}" ${repo_name} ${commit_hash} ${TOKEN} ${testname} ${link} "${description}"
}

trap "updateStatus FAILED" EXIT

updateStatus "INPROGRESS"

set -x
./ci.sh
set +x

updateStatus "SUCCESSFUL"
trap "" EXIT
