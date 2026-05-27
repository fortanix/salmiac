#!/usr/bin/env bash

script_dir=$(dirname "$(realpath "${BASH_SOURCE[0]})")")

container_name="enclaveos-test-${USER}"
image_name="localhost:5000/nginx-snp:latest"

docker run \
  --rm \
  --privileged \
  --name="${container_name}" \
  --runtime="runc" \
  -e ENCLAVEOS_DISABLE_DEFAULT_CERTIFICATE=true \
  -e ENCLAVEOS_DEBUG=debug \
  -e RUST_LOG=debug \
  "${image_name}"

echo "Press Enter to continue..."
read

docker container stop "${container_name}"
