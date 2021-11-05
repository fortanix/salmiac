#!/bin/sh

# Enclave startup code
./enclave --vsock-port 5006 --settings-path enclave-settings.json
