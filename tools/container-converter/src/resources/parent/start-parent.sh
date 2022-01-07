#!/bin/bash
# This is an entry point script for parent image.
# Its main purpose is to setup env vars for nitro tooling and pre-setup networking.
# Enclave start and connection code is applied dynamically to the bottom of this file by the converter.

# Allow job control in interactive mode. This is used by the code that is
# appended to this script by the converter.
set -m

# Setup nitro environment
source /etc/profile.d/nitro-cli-env.sh

# Check if nitro-cli is properly installed
nitro-cli --version

# Instruct the kernel to drop any incoming packets as
# those asdsawill be handled by the parent program
iptables -A INPUT -m socket -j ACCEPT
iptables -P INPUT DROP
ip a
ip link set dev eth0 mtu 1600
