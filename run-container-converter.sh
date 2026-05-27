#!/usr/bin/env bash

script_dir=$(dirname "$(realpath "${BASH_SOURCE[0]})")")

parent_image="parent-base-snp"
enclave_image="enclave-base"

docker run \
  --rm \
  -e SALMIAC_PLATFORM=snp \
  -e RUST_LOG=debug \
  -e ENCLAVEOS_DEBUG=debug \
  -e "PARENT_IMAGE=${parent_image}" \
  -e "ENCLAVE_IMAGE=${enclave_image}" \
  --name snp-converter \
  --user 0 \
  --privileged \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e PRESERVE_IMAGES=input,result \
  -v ./req.json:/app/req.json \
  snp-converter \
  --request-file /app/req.json