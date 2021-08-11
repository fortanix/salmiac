#!/bin/sh

# This is an entry point script for enclave.
# Its main purpose is to run vsock-proxy and client command.

./vsock-proxy server --vsock-port 5006 --remote-port 8080 &
