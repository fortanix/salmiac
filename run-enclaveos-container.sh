#!/usr/bin/env bash

script_dir=$(dirname "$(realpath "${BASH_SOURCE[0]})")")

container_name="enclaveos-test-${USER}"
image_name="localhost:5000/nginx-snp:latest"

if [ -z "$1" ]; then
  echo "Running default image \"${image_name}\""
else
  image_name="${1}"
  echo "Running image \"${image_name}\""
fi

cleanup() {
  docker container stop "${container_name}"
}

trap cleanup EXIT

docker run \
  --rm \
  --pull=always \
  --privileged \
  --name="${container_name}" \
  --runtime="runc" \
  -e ENCLAVEOS_DISABLE_DEFAULT_CERTIFICATE=false \
  -e ENCLAVEOS_DEBUG=debug \
  -e RUST_LOG=debug \
  "${image_name}"
