#!/bin/bash
# This is an entry point script for parent image.
# Its main purpose is to setup env vars for nitro tooling and pre-setup networking.
# Enclave start and connection code is applied dynamically to the bottom of this file by the converter.

# Setup nitro environment
source /etc/profile.d/nitro-cli-env.sh

# Check if nitro-cli is properly installed
nitro-cli --version

# Instruct the kernel to drop any incoming packets as
# those will be handled by the parent program
iptables -A INPUT -m socket -j ACCEPT
iptables -P INPUT DROP
