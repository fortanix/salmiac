#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$1"

mkdir -p \
  "${OUT_DIR}/compute/lib" \
  "${OUT_DIR}/utility/lib" \
  "${OUT_DIR}/utility/bin" \
  "${OUT_DIR}/firmware"

LDCONFIG_CACHE="$(ldconfig -p)"

resolve_lib() {
  local soname="$1"

  awk -v lib="${soname}" '
    $1 == lib || index($1, lib ".") == 1 {
      print $1 " " $NF
      exit
    }
  ' <<< "${LDCONFIG_CACHE}"
}

copy_lib() {
  local capability="$1"
  local soname="$2"
  local resolved
  local cache_name
  local src
  local dst_dir
  local copied_name

  resolved="$(resolve_lib "${soname}")"

  if [ -z "${resolved}" ]; then
    echo "ERROR: NVIDIA library not found through ldconfig: ${soname}" >&2
    exit 1
  fi

  cache_name="$(awk '{ print $1 }' <<< "${resolved}")"
  src="$(awk '{ print $2 }' <<< "${resolved}")"

  dst_dir="${OUT_DIR}/${capability}/lib"
  copied_name="$(basename "${src}")"

  echo "Staging ${capability} library: ${soname} from ${src}"
  cp -aL "${src}" "${dst_dir}/${copied_name}"

  ln -sf "${copied_name}" "${dst_dir}/${soname}"

  if [ "${cache_name}" != "${soname}" ] && [ "${cache_name}" != "${copied_name}" ]; then
    ln -sf "${copied_name}" "${dst_dir}/${cache_name}"
  fi
}

copy_bin() {
  local capability="$1"
  local bin="$2"
  local src
  local dst_dir

  src="$(command -v "${bin}" || true)"

  if [ -z "${src}" ]; then
    echo "ERROR: NVIDIA binary not found in PATH: ${bin}" >&2
    exit 1
  fi

  dst_dir="${OUT_DIR}/${capability}/bin"

  echo "Staging ${capability} binary: ${bin} from ${src}"
  cp -aL "${src}" "${dst_dir}/${bin}"
}

copy_firmware() {
  local found=0
  local src
  local dst

  for src in /lib/firmware/nvidia/*/gsp*.bin; do
    [ -e "${src}" ] || continue

    found=1
    dst="${OUT_DIR}/firmware/${src#/}"

    echo "Staging NVIDIA firmware: ${src} -> ${dst}"
    mkdir -p "$(dirname "${dst}")"
    cp -aL "${src}" "${dst}"
  done

  if [ "${found}" -eq 0 ]; then
    echo "ERROR: no NVIDIA GSP firmware found under /lib/firmware/nvidia/*/gsp*.bin" >&2
    find /lib/firmware \( -path '*nvidia*' -o -name 'gsp*.bin' \) -print 2>/dev/null || true
    exit 1
  fi
}

copy_libs() {
  local capability="$1"
  shift

  local lib
  for lib in "$@"; do
    copy_lib "${capability}" "${lib}"
  done
}

copy_bins() {
  local capability="$1"
  shift

  local bin
  for bin in "$@"; do
    copy_bin "${capability}" "${bin}"
  done
}

# referenced from https://github.com/NVIDIA/libnvidia-container/blob/main/src/nvc_info.c
#
# Commented out ones are in the list but not found.

compute_libs=(
  libcuda.so
  libcudadebugger.so
  libnvidia-opencl.so
  # libnvidia-gpucomp.so
  libnvidia-ptxjitcompiler.so
  # libnvidia-fatbinaryloader.so
  # libnvidia-allocator.so
  # libnvidia-compiler.so
  libnvidia-pkcs11.so
  libnvidia-pkcs11-openssl3.so
  libnvidia-nvvm.so
  # libnvidia-gpucomp.so
  libnvidia-tileiras.so
)

utility_libs=(
  libnvidia-ml.so
  # libnvidia-cfg.so
  # libnvidia-nscq.so
)

utility_bins=(
  nvidia-smi
  nvidia-debugdump
)

copy_libs compute "${compute_libs[@]}"
copy_libs utility "${utility_libs[@]}"
copy_bins utility "${utility_bins[@]}"

copy_firmware

find "${OUT_DIR}" -maxdepth 6 \( -type f -o -type l \) | sort
