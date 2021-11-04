#!/bin/bash
# This is an entry point script for parent image.
# Its main purpose is to setup env vars for nitro tooling and allocate resources for the enclave.
# Enclave start and connection code is applied dynamically to the bottom of this file by the converter.

# Setup nitro environment
source /etc/profile.d/nitro-cli-env.sh

# Debug: check if nitro-cli is properly installed
nitro-cli --version

# Copy allocator settings and start resource allocator service
cp allocator.yaml /etc/nitro_enclaves/allocator.yaml
systemctl start nitro-enclaves-allocator.service
systemctl enable nitro-enclaves-allocator.service
systemctl status nitro-enclaves-allocator.service

iptables -A INPUT -m socket -j ACCEPT
iptables -P INPUT DROP
