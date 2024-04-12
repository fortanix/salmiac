#!/bin/bash

set -exo pipefail

mkdir -p ./staging

# Move the converter binary into staging, the input argument to the script
# determines whether a release or debug converter is used
cp ../tools/container-converter/target/$1/container-converter ./staging
mv ./staging/container-converter ./staging/server

# Package the enclave and parent base images for the converter
docker save -o ./staging/nitro-enclave-base.tar enclave-base
docker save -o ./staging/nitro-parent-base.tar parent-base

# The Dockerfile used to build the converter uses a prebuilt parent-base
# image by default which resides in the Fortanix ECR repository. The users
# of this script can use the parent-base image which was built by them.
docker tag parent-base 513076507034.dkr.ecr.us-west-1.amazonaws.com/nitro-parent-base:1.1.3

# Build the converter
docker build -t converter .
