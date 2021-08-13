#!/bin/sh

# This is an entry point script for enclave.
# Its main purpose is to run vsock-proxy and client command.

./vsock-proxy enclave --vsock-port 5006 &
