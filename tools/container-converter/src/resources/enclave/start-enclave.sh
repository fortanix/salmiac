#!/bin/sh

# Allow job control in interactive mode. This is used by the code that is
# appended to this script by the converter.
set -m

# Enclave startup code
./enclave --vsock-port 5006 --settings-path enclave-settings.json
