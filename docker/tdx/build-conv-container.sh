#!/bin/bash

set -exo pipefail

mkdir -p ./staging

# Move the converter binary into staging, the input argument to the script
# determines whether a release or debug converter is used
cp ../../tools/container-converter/target/$1/container-converter ./staging
mv ./staging/container-converter ./staging/server

# Package the enclave and parent base images for the converter
docker save -o ./staging/enclave-base.tar enclave-base
docker save -o ./staging/enclave-base-gpu.tar enclave-base-gpu
docker save -o ./staging/parent-base.tar parent-base-tdx

# Build the converter
docker build --no-cache -t tdx-converter .
