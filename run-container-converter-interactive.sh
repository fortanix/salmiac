#!/usr/bin/env bash

script_dir=$(dirname "$(realpath "${BASH_SOURCE[0]})")")

converter_name="snp-converter"
req_file="${script_dir}/req.json"

if [ -z "$1" ]; then
  echo "Using default request file path \"${req_file}\""
else
  req_file="${1}"
  echo "Using request file \"${req_file}\""
fi

docker run \
  --rm \
  -it \
  -e RUST_LOG=debug \
  -e ENCLAVEOS_DEBUG=debug \
  --name "${converter_name}" \
  --user 0 \
  --privileged \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e PRESERVE_IMAGES=input,result \
  -v "${req_file}:/app/req.json" \
  --entrypoint="/usr/bin/bash" \
  "${converter_name}"

# Run the following command to do the conversion:
# RUST_LOG=debug ./server --request-file ./req.json

exit_code="${?}"
if [ "${exit_code}" -ne 0 ] ; then
  echo "Conversion failed with code ${exit_code}"
  exit "${exit_code}"
fi