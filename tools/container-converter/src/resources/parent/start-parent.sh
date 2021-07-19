#!/bin/bash
# Setup nitro environment
source /etc/profile.d/nitro-cli-env.sh

# Debug: check if nitro-cli is properly installed
nitro-cli --version

# Copy allocator settings and start resource allocator service
cp allocator.yaml /etc/nitro_enclaves/allocator.yaml
systemctl start nitro-enclaves-allocator.service
systemctl enable nitro-enclaves-allocator.service