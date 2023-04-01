Pod::Spec.new do |s|
  s.name             = 'LoamSdk'
  s.license          = 'MIT'
  s.author           = { 'Nora Trapp' => 'nora@loam.me' }
  s.version          = '0.0.1'
  s.summary          = 'A Swift wrapper library for interfacing with the Loam service.'

  s.homepage         = 'https://github.com/loam-security/loam-sdk'
  s.source           = { :git => 'https://github.com/loam-security/loam-sdk.git', :tag => "v#{s.version}" }

  s.swift_version    = '5'
  s.platform         = :ios, '13'

  s.source_files = ['swift/Sources/**/*.swift']
  s.preserve_paths = [
    'target/*/release/libloam_sdk_ffi.a',
    'target/*/release/include',
    'swift/Sources/LoamSdkFfi'
  ]

  s.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/swift/Sources/LoamSdkFfi $(PODS_TARGET_SRCROOT)/target/${CARGO_BUILD_TARGET}/release/include',
      'SWIFT_INCLUDE_PATHS' => '$(HEADER_SEARCH_PATHS)',

      'OTHER_LDFLAGS' => '$(PODS_TARGET_SRCROOT)/target/$(CARGO_BUILD_TARGET)/release/libloam_sdk_ffi.a',

      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=arm64]' => 'aarch64-apple-ios-sim',
      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=*]' => 'x86_64-apple-ios',
      'CARGO_BUILD_TARGET[sdk=iphoneos*]' => 'aarch64-apple-ios',

      'ARCHS[sdk=iphonesimulator*]' => 'x86_64 arm64',
      'ARCHS[sdk=iphoneos*]' => 'arm64',
  }

  s.prepare_command = %Q(
    set -euo pipefail
    CARGO_BUILD_TARGET=aarch64-apple-ios swift/build-ffi.sh --release
    CARGO_BUILD_TARGET=x86_64-apple-ios swift/build-ffi.sh --release
    CARGO_BUILD_TARGET=aarch64-apple-ios-sim swift/build-ffi.sh --release
    swift/build-ffi.sh --generate-ffi
  )
end
