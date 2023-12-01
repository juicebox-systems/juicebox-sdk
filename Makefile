all: ffi jni

FFI_TARGETS = aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim

$(FFI_TARGETS): %: cargo/juicebox_sdk_ffi/% copy_artifacts/juicebox_sdk_ffi/%

ffi: $(FFI_TARGETS)

cargo/juicebox_sdk_ffi/%:
	CARGO_BUILD_TARGET=${*} ./swift/ffi.sh --release

copy_artifacts/juicebox_sdk_ffi/%: cargo/juicebox_sdk_ffi/%
	rm -rf "artifacts/ffi/${*}"
	mkdir -p "artifacts/ffi/${*}"
	cp "target/${*}/release/libjuicebox_sdk_ffi.a" "artifacts/ffi/${*}"
	cp "target/${*}/release/libjuicebox_sdk_ffi.d" "artifacts/ffi/${*}"
	cp -r "target/${*}/release/include" "artifacts/ffi/${*}"

jni:
	./android/jni.sh
