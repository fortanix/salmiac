#!/usr/bin/env bash

set -Eeox pipefail

if [ $# -ge 1 ]; then
    RELEASE=$1
fi

docker build --target build -t test-salmiac --build-arg RELEASE=$RELEASE -f docker/vsock-proxy/Dockerfile .
