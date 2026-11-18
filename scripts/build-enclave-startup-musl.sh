#!/bin/bash

set -euo pipefail

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/inc.sh"

target=x86_64-unknown-linux-musl

usage() {
    echo "Usage: ${0} [--build-type debug|release] [--out-path PATH]"
    echo "Builds enclave-startup for x86_64-unknown-linux-musl (default: debug)."
    echo "The optional output path copies the built binary to the specified destination."
}

error() {
    echo "Error: $*" >&2
    exit 1
}

check_prequisites() {
    local target_libdir
    local -a std_libraries

    target_libdir="$(rustc --print target-libdir --target "$target")" || error "Unable to query the active Rust toolchain"
    std_libraries=("$target_libdir"/libstd-*.rlib)
    [[ -f "${std_libraries[0]}" ]] || error "Rust target $target is not installed; run: rustup target add $target"
}

build_type=debug
out_path=""
while (( $# > 0 )); do
    case "$1" in
        --build-type)
            (( $# >= 2 )) || error "--build-type requires debug or release"
            build_type="$2"
            shift 2
            ;;
        --build-type=*)
            build_type="${1#*=}"
            shift
            ;;
        --out-path)
            (( $# >= 2 )) || error "--out-path requires a destination path"
            [[ -n "$2" && "$2" != --* ]] || error "--out-path requires a destination path"
            out_path="$(realpath -m -- "$2")"
            shift 2
            ;;
        --out-path=*)
            [[ -n "${1#*=}" ]] || error "--out-path requires a destination path"
            out_path="$(realpath -m -- "${1#*=}")"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) error "Unknown argument: $1" ;;
    esac
done

case "$build_type" in
    debug|release) ;;
    *) error "Invalid build type '$build_type'; expected debug or release" ;;
esac

check_prequisites

cargo_args=(build --locked --target="$target")
if [[ "$build_type" == release ]]; then
    cargo_args+=(--release)
fi

echo "Building enclave-startup"
cd "${repo_root}/enclave-startup"
target_dir="${CARGO_TARGET_DIR:-target}"
cargo "${cargo_args[@]}" --target-dir="$target_dir"

if [[ -n "$out_path" ]]; then
    mkdir -p "$(dirname "$out_path")"
    cp -- "${target_dir}/${target}/${build_type}/enclave-startup" "$out_path"
fi
