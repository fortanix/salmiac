#!/bin/bash

set -exo pipefail

# Login to ECR
aws ecr get-login-password | docker login --username AWS --password-stdin 513076507034.dkr.ecr.us-west-1.amazonaws.com

# Build application tests container
FLAVOR=debug
if [ -z "$SKIP_RUNNING_TESTS" ]; then
  make tests-container FLAVOR=$FLAVOR
  TESTS_CONTAINER_TAG=$(cat build/nitro-$FLAVOR/tests-container-tag)
  TESTS_CONTAINER_ECR="513076507034.dkr.ecr.us-west-1.amazonaws.com/salmiac-github-ci/$TESTS_CONTAINER_TAG"

  docker load -i build/nitro-$FLAVOR/salmiac-tests-container.tar.gz
  docker tag $TESTS_CONTAINER_TAG $TESTS_CONTAINER_ECR
  docker push $TESTS_CONTAINER_ECR

  # Remove built images from local repository
  docker image rm -f $TESTS_CONTAINER_TAG
  docker image rm -f $TESTS_CONTAINER_ECR
fi

# $GITHUB_ENV is a special variable which allows us to setup env vars in-between job stages.
# More info in https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-environment-variable
echo "TESTS_CONTAINER_ECR="$TESTS_CONTAINER_ECR >> $GITHUB_ENV