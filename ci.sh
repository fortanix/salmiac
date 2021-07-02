#!/usr/bin/env bash

set -Eeuox pipefail

docker build --target build -t test-salmiac -f docker/vsock-proxy/Dockerfile .
