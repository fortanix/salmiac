#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

docker build \
  -t parent-base-simulator:latest \
  "$script_dir"
