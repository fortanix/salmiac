#!/usr/bin/env bash
set -euo pipefail

profile="$1"
artifact_dir="$2"
image_tag="${3:-simulator-converter:latest}"

case "$profile" in
  debug|release)
    ;;
  *)
    echo "error: profile must be 'debug' or 'release'"
    usage
    exit 1
    ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
artifact_dir="$(cd "$artifact_dir" && pwd)"

converter_bin="$repo_root/tools/container-converter/target/$profile/container-converter"

if [ ! -f "$converter_bin" ]; then
  echo "error: converter binary not found at $converter_bin"
  exit 1
fi

if [ ! -f "$artifact_dir/init" ]; then
  echo "error: init not found at $artifact_dir/init"
  exit 1
fi

if [ ! -f "$artifact_dir/kernel" ]; then
  echo "error: kernel not found at $artifact_dir/kernel"
  exit 1
fi

rm -rf "$script_dir/staging"
mkdir -p "$script_dir/staging/blobs"

cp "$converter_bin" "$script_dir/staging/server"
cp "$artifact_dir/init" "$script_dir/staging/blobs/init"
cp "$artifact_dir/kernel" "$script_dir/staging/blobs/kernel"

docker save -o "$script_dir/staging/enclave-base.tar" enclave-base-simulator:latest
docker save -o "$script_dir/staging/parent-base.tar" parent-base-simulator:latest

docker build -t "$image_tag" "$script_dir"
