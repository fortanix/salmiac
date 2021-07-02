#!/usr/bin/env bash

set -Eeuo pipefail

docker build --target build -t test-salmiac -f docker/vsock-proxy/Dockerfile .