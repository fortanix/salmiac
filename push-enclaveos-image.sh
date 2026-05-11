#!/usr/bin/env bash

script_dir=$(dirname "$(realpath "${BASH_SOURCE[0]})")")

launchpad_hostname="launchpad-7"

request_file="${script_dir}/req.json"

image_name="$(jq -r '.output_image.name' "${request_file}")"

registry_port="5000"
registry_path="localhost:${registry_port}"
registry_tagged_image_name="${registry_path}/${image_name}"

# Tag the image for a registry
docker tag "${image_name}" "${registry_tagged_image_name}"

#archive_path="${script_dir}/${image_name}.tar.gz"
#
#docker save "${image_name}" | gzip > "${archive_path}"
#
#rsync -auxPAX "${archive_path}" "${launchpad_hostname}:~/${image_name}.tar.gz"

#exit

# Push the image to the Launchpad 7 Docker registry through an SSH tunnel
socket_name="launchpad-registry-tunnel-socket"

ssh -M -S "${socket_name}" -f -N -T -L "${registry_port}:localhost:${registry_port}" "${launchpad_hostname}"

ssh -S "${socket_name}" -O check "${launchpad_hostname}"

docker push "${registry_tagged_image_name}"

ssh -S "${socket_name}" "${launchpad_hostname}" docker pull "${registry_tagged_image_name}"

ssh -S "${socket_name}" -O exit "${launchpad_hostname}"