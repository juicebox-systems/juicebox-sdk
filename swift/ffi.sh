#!/bin/bash

set -euo pipefail

export CARGO_PROFILE_RELEASE_DEBUG=1
export CARGO_PROFILE_RELEASE_LTO=fat

usage() {
  cat >&2 <<END
USAGE: $(basename "$0") [-d|-r] [-v] [--generate|--verify]

Specify CARGO_BUILD_TARGET for cross-compilation during builds.

OPTIONS:
  -d, --debug             debug build (default)
  -r, --release           release build
  -v, --verbose           verbose build

  --generate              regenerate cbindgen headers
  --verify                verify cbindgen headers

  -h, --help              show this help information
END
}

RELEASE=
VERBOSE=

RUN_CBINDGEN=
VERIFY_CBINDGEN=

while [ "${1:-}" != "" ]; do
  case $1 in
    -d | --debug )
      RELEASE=
      ;;
    -r | --release )
      RELEASE=1
      ;;
    -v | --verbose )
      VERBOSE=1
      ;;
    --generate )
      RUN_CBINDGEN=1
      ;;
    --verify )
      RUN_CBINDGEN=1
      VERIFY_CBINDGEN=1
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

if [[ -n "${CARGO_BUILD_TARGET:-}" ]] && ! (rustup target list --installed | grep -q "${CARGO_BUILD_TARGET:-}"); then
  echo "error: ${CARGO_BUILD_TARGET} not installed" >&2
  printf "get it by running: \n\trustup target add ${CARGO_BUILD_TARGET}\n" >&2
  exit 1
fi

echo cargo build -p juicebox_sdk_ffi ${RELEASE:+--release} ${VERBOSE:+--verbose} ${CARGO_BUILD_TARGET:+--target $CARGO_BUILD_TARGET}
cargo build -p juicebox_sdk_ffi ${RELEASE:+--release} ${VERBOSE:+--verbose} ${CARGO_BUILD_TARGET:+--target $CARGO_BUILD_TARGET}

FFI_HEADER_PATH=swift/Sources/JuiceboxSdkFfi/juicebox-sdk-ffi.h

if [[ -n "${RUN_CBINDGEN}" ]]; then

  if ! command -v cbindgen > /dev/null; then
    echo 'error: cbindgen not found' >&2
    if command -v cargo > /dev/null; then
      printf "get it by running: \n\tcargo install cbindgen --vers '^0.24'\n" >&2
    fi
    exit 1
  fi

  if [[ -n "${VERIFY_CBINDGEN}" ]]; then
    echo diff -u "${FFI_HEADER_PATH}" "<(cbindgen -q ${RELEASE:+--profile release} rust/sdk/bridge/ffi)"
    if ! diff -u "${FFI_HEADER_PATH}"  <(cbindgen -q ${RELEASE:+--profile release} rust/sdk/bridge/ffi); then
      echo
      echo 'error: juicebox-sdk-ffi.h not up to date; run' "$0" '--generate`' >&2
      exit 1
    fi
  else
    echo cbindgen ${RELEASE:+--profile release} -o "${FFI_HEADER_PATH}" rust/sdk/bridge/ffi
    cbindgen ${RELEASE:+--profile release} -o "${FFI_HEADER_PATH}" rust/sdk/bridge/ffi 2>&1
  fi
fi
