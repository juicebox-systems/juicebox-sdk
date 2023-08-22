#!/bin/bash

set -euo pipefail

usage() {
  cat >&2 <<END
USAGE: $(basename "$0") [-d|-r] [-v]

Builds the necessary Rust JNI dependencies for Android.

OPTIONS:
  -v, --verbose           verbose build

  -h, --help              show this help information
END
}

VERBOSE=

while [ "${1:-}" != "" ]; do
  case $1 in
    -v | --verbose )
      VERBOSE=1
      ;;
    -h | --help )
      usage
      exit
      ;;
    * )
      usage
      exit 2
  esac
  shift
done

if ! command -v rustup > /dev/null && [[ -d ~/.cargo/bin ]]; then
  PATH=~/.cargo/bin:$PATH
fi

if ! command -v rustup > /dev/null; then
  if ! command -v cargo > /dev/null; then
    echo 'error: cargo not found' >&2
    exit 1
  fi

  echo 'warning: rustup not found" >&2'
  return
fi

SCRIPT_DIR=$(dirname "$0")
cd "${SCRIPT_DIR}"/..

ANDROID_LIB_DIR=android/libs

TARGETS=("aarch64-linux-android arm64-v8a" "armv7-linux-androideabi armeabi-v7a" "x86_64-linux-android x86_64" "i686-linux-android x86")

ANDROID_TOOLCHAIN_DIR=$(echo "${ANDROID_NDK_HOME}"/toolchains/llvm/prebuilt/*/bin/)
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${ANDROID_TOOLCHAIN_DIR}/aarch64-linux-android21-clang"
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="${ANDROID_TOOLCHAIN_DIR}/armv7a-linux-androideabi21-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="${ANDROID_TOOLCHAIN_DIR}/x86_64-linux-android21-clang"
export CARGO_TARGET_I686_LINUX_ANDROID_LINKER="${ANDROID_TOOLCHAIN_DIR}/i686-linux-android21-clang"

for target in "${TARGETS[@]}"; do
    set -- $target
    CARGO_BUILD_TARGET=$1
    ANDROID_BUILD_TARGET=$2

    if ! (rustup target list --installed | grep -q "${CARGO_BUILD_TARGET}"); then
        echo "error: ${CARGO_BUILD_TARGET} not installed" >&2
        printf "get it by running: \n\trustup target add ${CARGO_BUILD_TARGET}\n" >&2
        exit 1
    fi

    echo cargo build -p juicebox_sdk_jni --release ${VERBOSE:+--verbose} --target ${CARGO_BUILD_TARGET}
    cargo build -p juicebox_sdk_jni --release ${VERBOSE:+--verbose} --target ${CARGO_BUILD_TARGET}

    echo mkdir -p "${ANDROID_LIB_DIR}/${ANDROID_BUILD_TARGET}"
    mkdir -p "${ANDROID_LIB_DIR}/${ANDROID_BUILD_TARGET}"

    echo mv "target/${CARGO_BUILD_TARGET}/release/libjuicebox_sdk_jni.so" "${ANDROID_LIB_DIR}/${ANDROID_BUILD_TARGET}"
    mv "target/${CARGO_BUILD_TARGET}/release/libjuicebox_sdk_jni.so" "${ANDROID_LIB_DIR}/${ANDROID_BUILD_TARGET}"
done
