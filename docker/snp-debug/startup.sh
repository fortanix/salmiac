#!/usr/bin/env bash

set -x

script_dir=$(dirname "$(realpath "${BASH_SOURCE[0]})")")

default_cert_dir="/opt/fortanix/enclave-os/default_cert";
default_key_file="app_private.pem";
default_cert_file="app_public.pem"

echo "USER: ${USER}"

env

ls -la "${default_cert_dir}"

ls -la "/tmp"