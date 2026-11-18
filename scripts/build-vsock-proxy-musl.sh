#!/bin/bash

set -euo pipefail

# shellcheck source-path=SCRIPTDIR
source "$(dirname "${BASH_SOURCE[0]}")/inc.sh"

musl_cc=x86_64-linux-musl-gcc
target=x86_64-unknown-linux-musl
libpcap_version=1.10.7
cache_dir="/tmp/salmiac-musl/libpcap-${libpcap_version}-r0-x86_64"

usage() {
    echo "Usage: ${0} [--build-type debug|release] [--enclave-out-path PATH] [--parent-out-path PATH] [--remove-cache]"
    echo "Builds vsock-proxy for x86_64-unknown-linux-musl (default: debug)."
    echo "Optional output paths copy the built binaries to the specified destinations."
    echo "Set SALMIAC_PLATFORM to select the platform, for example nitro."
}

error() {
    echo "Error: $*" >&2
    exit 1
}

check_prequisites() {
    local target_libdir
    local -a std_libraries

    command -v "$musl_cc" >/dev/null || error "Musl C compiler not found, install musl-tools"
    command -v rustc >/dev/null || error "rustc is not available"

    target_libdir="$(rustc --print target-libdir --target "$target")" || error "Unable to query the active Rust toolchain"
    std_libraries=("$target_libdir"/libstd-*.rlib)
    [[ -f "${std_libraries[0]}" ]] || error "Rust target $target is not installed"
}

download_libpcap() (
    local libpcap_package="libpcap-dev-${libpcap_version}-r0.apk"
    local libpcap_sha256=55e1c806f8fa6107b2fda4940f4ccbba938583b67e0e46ebf259362f69cf9003
    local download_dir

    if [[ ! -s "${cache_dir}/libpcap.a" ]]; then
        mkdir -p "$cache_dir"
        download_dir="$(mktemp -d "${cache_dir}/download.XXXXXX")"
        trap 'rm -rf -- "$download_dir"' EXIT

        echo "Downloading musl libpcap ${libpcap_version} from Alpine Linux..."
        curl --fail --location --retry 3 \
            --output "${download_dir}/${libpcap_package}" \
            "https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/${libpcap_package}"
        printf '%s  %s\n' "$libpcap_sha256" "${download_dir}/${libpcap_package}" | sha256sum --check -
        tar --warning=no-unknown-keyword --ignore-zeros \
            -xzf "${download_dir}/${libpcap_package}" \
            -C "$download_dir" usr/lib/libpcap.a
        [[ -s "${download_dir}/usr/lib/libpcap.a" ]] || error "Downloaded package does not contain libpcap.a"
        mv "${download_dir}/usr/lib/libpcap.a" "${cache_dir}/libpcap.a"
    else
        echo "Using cached musl libpcap: ${cache_dir}/libpcap.a"
    fi
)

build_type=debug
enclave_out_path=""
parent_out_path=""
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
        --enclave-out-path|--parent-out-path)
            (( $# >= 2 )) || error "$1 requires a destination path"
            [[ -n "$2" && "$2" != --* ]] || error "$1 requires a destination path"
            destination="$(realpath -m -- "$2")"
            if [[ "$1" == --enclave-out-path ]]; then
                enclave_out_path="$destination"
            else
                parent_out_path="$destination"
            fi
            shift 2
            ;;
        --enclave-out-path=*)
            [[ -n "${1#*=}" ]] || error "--enclave-out-path requires a destination path"
            enclave_out_path="$(realpath -m -- "${1#*=}")"
            shift
            ;;
        --parent-out-path=*)
            [[ -n "${1#*=}" ]] || error "--parent-out-path requires a destination path"
            parent_out_path="$(realpath -m -- "${1#*=}")"
            shift
            ;;
        --remove-cache)
            rm -rf -- "$cache_dir"
            echo "Cache dir: $cache_dir removed"
            exit 0
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
download_libpcap

export LIBPCAP_LIBDIR="$cache_dir"
export LIBPCAP_VER="$libpcap_version"
export CC_x86_64_unknown_linux_musl="$musl_cc"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$musl_cc"

cargo_args=(build --locked --target="$target")
if [[ "$build_type" == release ]]; then
    cargo_args+=(--release)
fi

echo "Building vsock-proxy"
cd "${repo_root}/vsock-proxy"
target_dir="${CARGO_TARGET_DIR:-target}"
cargo "${cargo_args[@]}" --target-dir="$target_dir"

# Copy binaries to destinations if provided
if [[ -n "$enclave_out_path" ]]; then
    mkdir -p "$(dirname "$enclave_out_path")"
    cp "${target_dir}/${target}/${build_type}/enclave" "$enclave_out_path"
fi

if [[ -n "$parent_out_path" ]]; then
    mkdir -p "$(dirname "$parent_out_path")"
    cp "${target_dir}/${target}/${build_type}/parent" "$parent_out_path"
fi
