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

# Check if nbd-server is properly installed
nbd-server -V

# Instruct the kernel to drop any incoming packets not on the loopback network, as
# those will be handled by the parent program
# Accept packets on the input chain i.e. packets coming into the
# host. The -m option allows for packet matching - in this case
# all open, bound listening sockets on TCP/UDP
iptables -A INPUT -m socket -j ACCEPT

# Accept incoming traffic on the loopback device interface
# This allows salmiac to process dns traffic when docker
# uses its embedded dns resolver
iptables -A INPUT -i lo -s 0.0.0.0/0 -d 0.0.0.0/0 -j ACCEPT

# Drop all other incoming traffic
iptables -P INPUT DROP
