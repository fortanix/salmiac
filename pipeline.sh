#!/usr/bin/env bash

set -Eeuox pipefail

source tools/bitbucket-api/bitbucket-buildstatus.sh

testname="salmiac-pr"
description="this is the description of the test"
link="https://jenkins.fortanix.net/job/${JOB_NAME}/${BUILD_NUMBER}/"

updateStatus () {
    result=$1
    echo "Updating status on commit ${commit_hash} to ${result}"
    BitBucketGetAccessToken "${bitbucket_key}" "${bitbucket_secret}"
	BitBucketSetStatus "${result}" ${repo_name} ${commit_hash} ${TOKEN} ${testname} ${link} "${description}"
}

trap "updateStatus FAILED" EXIT

updateStatus "INPROGRESS"

./ci.sh

updateStatus "SUCCESSFUL"
trap "" EXIT
