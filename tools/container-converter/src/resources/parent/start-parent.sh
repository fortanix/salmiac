#!/bin/bash
# Setup nitro environment
source /etc/profile.d/nitro-cli-env.sh

# Debug: check if nitro-cli is properly installed
nitro-cli --version

# Copy allocator settings and start resource allocator service
cp allocator.yaml /etc/nitro_enclaves/allocator.yaml
systemctl start nitro-enclaves-allocator.service
systemctl enable nitro-enclaves-allocator.service

# Run rust proxy in parent
#./vsock-proxy proxy --remote-port 5000 --vsock-port 5006 &

# Run the enclave
#nitro-cli run-enclave --eif-path ubuntu-networking-enclave.eif  --enclave-cid 4 --cpu-count 2 --memory 1040 --debug-mode

# Debug: output logs and console output from the enclave
#cat /var/log/nitro_enclaves/*
#ID=$(nitro-cli describe-enclaves | jq '.[0] | .EnclaveID')
#ID="${ID%\"}"
#ID="${ID#\"}"

#nitro-cli console --enclave-id $ID

