#!/bin/bash
set -e

# Extracts filesystem layers using `skopeo`, extracts the filesystem using `umoci` and builds the CPIO archive using `cpio`.

function show_usage() {
    echo "Usage: $0 [OPTION...]
        [-h]                Show help
        [-k]                Keep intermediary files (default: false)
        [-o output_file]    CPIO output file (default: stdout)
        -i <oci_url>        Image URL supported by skopeo copy (containers-storage, dir, docker, docker-archive, docker-daemon, oci, oci-archive, ostree, sif, tarball)"
}

keep_files=0
output_file=/dev/stdout
tag=salmiac
while getopts "hi:ko:" option; do
    case $option in
        h)
            echo "Convert a container image to a CPIO New ASCII format"
            show_usage
            exit 0
            ;;
        i)
            oci_url="$OPTARG"
            ;;
        k)
            keep_files=1
            ;;
        o)
            output_file=$(realpath "$OPTARG")
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
done

if [ -z "${oci_url}" ]; then
    show_usage
    exit 1
fi

# Create temporary directory to extract image layers
skopeo_tmp_dir="$(mktemp --directory --tmpdir="${PWD}")"

# Copy image filesystem layers
echo skopeo copy "${oci_url}" "oci:${skopeo_tmp_dir}:${tag}" >&2
skopeo copy "${oci_url}" "oci:${skopeo_tmp_dir}:${tag}" >&2

# Create temporary directory to unpack rootfs
umoci_tmp_dir="$(mktemp --directory --tmpdir="${PWD}")"

# Extract image into a bundle
echo umoci unpack --rootless --image "${skopeo_tmp_dir}:${tag}" "${umoci_tmp_dir}" >&2
umoci unpack --rootless --image "${skopeo_tmp_dir}:${tag}" "${umoci_tmp_dir}"

pushd "${umoci_tmp_dir}/rootfs" >&2
find . | cpio --create --format newc --owner 0:0 > "${output_file}"
popd > /dev/null >&2

if [ $keep_files == 0 ]; then
    rm -fr ${skopeo_tmp_dir} >&2
    rm -fr ${umoci_tmp_dir} >&2
fi
