#!/bin/sh

# This is an entry point script for enclave.
# Its main purpose is to run vsock-proxy and client command.

./enclave --vsock-port 5006 --settings-path enclave-settings.json &
