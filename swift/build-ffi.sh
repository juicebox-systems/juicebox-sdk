#!/bin/bash

set -euo pipefail

export CARGO_PROFILE_RELEASE_DEBUG=1
export CARGO_PROFILE_RELEASE_LTO=fat

usage() {
  cat >&2 <<END
Usage: $(basename "$0") [-d|-r] [-v] [--generate-ffi|--verify-ffi]

Options:
  -d -- debug build (default)
  -r -- release build
  -v -- verbose build

  --generate-ffi -- regenerate ffi headers
  --verify-ffi   -- verify that ffi headers are up to date

Use CARGO_BUILD_TARGET for cross-compilation (such as for iOS).
END
}

check_cbindgen() {
  if ! command -v cbindgen > /dev/null; then
    echo 'error: cbindgen not found in PATH' >&2
    if command -v cargo > /dev/null; then
      echo 'note: get it by running' >&2
      printf "\n\t%s\n\n" "cargo install cbindgen --vers '^0.16'" >&2
    fi
    exit 1
  fi
}

echo_then_run() {
  echo "$@"
  "$@"
}

RELEASE_BUILD=
VERBOSE=
SHOULD_CBINDGEN=
CBINDGEN_VERIFY=

while [ "${1:-}" != "" ]; do
  case $1 in
    -d | --debug )
      RELEASE_BUILD=
      ;;
    -r | --release )
      RELEASE_BUILD=1
      ;;
    -v | --verbose )
      VERBOSE=1
      ;;
    --generate-ffi )
      SHOULD_CBINDGEN=1
      ;;
    --verify-ffi )
      SHOULD_CBINDGEN=1
      CBINDGEN_VERIFY=1
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
  echo 'note: get it by running' >&2
  printf "\n\t%s\n\n" "rustup +${RUSTUP_TOOLCHAIN:stable} target add ${CARGO_BUILD_TARGET}" >&2
  exit 1
fi

echo_then_run cargo build -p loam-sdk-ffi ${RELEASE_BUILD:+--release} ${VERBOSE:+--verbose} ${CARGO_BUILD_TARGET:+--target $CARGO_BUILD_TARGET}

FFI_HEADER_PATH=swift/Sources/LoamSdkFfi/loam-sdk-ffi.h

if [[ -n "${SHOULD_CBINDGEN}" ]]; then
  check_cbindgen
  if [[ -n "${CBINDGEN_VERIFY}" ]]; then
    echo diff -u "${FFI_HEADER_PATH}" "<(cbindgen -q ${RELEASE_BUILD:+--profile release} rust/bridge/ffi)"
    if ! diff -u "${FFI_HEADER_PATH}"  <(cbindgen -q ${RELEASE_BUILD:+--profile release} rust/bridge/ffi); then
      echo
      echo 'error: loam-sdk-ffi.h not up to date; run' "$0" '--generate-ffi' >&2
      exit 1
    fi
  else
    echo cbindgen ${RELEASE_BUILD:+--profile release} -o "${FFI_HEADER_PATH}" rust/bridge/ffi
    cbindgen ${RELEASE_BUILD:+--profile release} -o "${FFI_HEADER_PATH}" rust/bridge/ffi 2>&1
  fi
fi
