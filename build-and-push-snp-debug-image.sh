#!/usr/bin/env bash

script_dir=$(dirname "$(realpath "${BASH_SOURCE[0]})")")

launchpad_hostname="launchpad-7"


debug_image_dir="${script_dir}/docker/snp-debug"
request_file="${debug_image_dir}/req.json"

input_image_name="$(jq -r '.input_image.name' "${request_file}")"
output_image_name="$(jq -r '.output_image.name' "${request_file}")"

registry_port="5000"
registry_path="localhost:${registry_port}"
registry_tagged_image_name="${registry_path}/${output_image_name}"

# Build the image
pushd "${debug_image_dir}" >/dev/null || exit

docker build -t "${input_image_name}" .

popd >/dev/null || exit

"${script_dir}/run-container-converter.sh" "${request_file}"

exit_code="${?}"
if [ "${exit_code}" -ne 0 ] ; then
  echo "Conversion for image \"${input_image_name}\" failed with code ${exit_code}"
  exit "${exit_code}"
fi

# Tag the image for a registry
docker tag "${output_image_name}" "${registry_tagged_image_name}"

# Push the image to the Launchpad 7 Docker registry through an SSH tunnel
socket_name="launchpad-registry-tunnel-socket"

ssh -M -S "${socket_name}" -f -N -T -L "${registry_port}:localhost:${registry_port}" "${launchpad_hostname}"

ssh -S "${socket_name}" -O check "${launchpad_hostname}"

docker push "${registry_tagged_image_name}"

ssh -S "${socket_name}" "${launchpad_hostname}" docker pull "${registry_tagged_image_name}"

ssh -S "${socket_name}" -O exit "${launchpad_hostname}"