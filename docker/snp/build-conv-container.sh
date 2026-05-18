#!/bin/bash

set -exo pipefail

mkdir -p ./staging

# Move the converter binary into staging, the input argument to the script
# determines whether a release or debug converter is used
cp ../../tools/container-converter/target/$1/container-converter ./staging
mv ./staging/container-converter ./staging/server

# Package the enclave and parent base images for the converter
docker save -o ./staging/enclave-base.tar enclave-base
docker save -o ./staging/enclave-base-gpu.tar enclave-base-snp-gpu
docker save -o ./staging/parent-base.tar parent-base-snp

# Stage sev-snp-measure tooling for the converter image
cp -r ../../tools/sev-snp-measure ./staging/sev-snp-measure

# Build the converter
docker build -t snp-converter .
#docker build --no-cache -t snp-converter .

