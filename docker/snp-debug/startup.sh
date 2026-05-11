#!/usr/bin/env bash

script_dir=$(dirname "$(realpath "${BASH_SOURCE[0]})")")

default_cert_dir="/opt/fortanix/enclave-os/default_cert";
default_key_file="app_private.pem";
default_cert_file="app_public.pem"

ls -la "${default_cert_dir}"