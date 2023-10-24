Pod::Spec.new do |s|
  s.name             = 'JuiceboxSdk'
  s.license          = 'MIT'
  s.author           = { 'Nora Trapp' => 'nora@juicebox.me' }
  s.version          = '0.2.1'
  s.summary          = 'A Swift wrapper library for interfacing with the Juicebox service.'

  s.homepage         = 'https://github.com/juicebox-systems/juicebox-sdk'
  s.source           = { :git => 'git@github.com:juicebox-systems/juicebox-sdk.git', :tag => "#{s.version}" }

  s.swift_version    = '5'
  s.platform         = :ios, '13'

  s.source_files = ['swift/Sources/**/*.swift']
  s.preserve_paths = [
    'target/*/release/libjuicebox_sdk_ffi.a',
    'target/*/release/include',
    'swift/Sources/JuiceboxSdkFfi',
  ]

  s.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/swift/Sources/JuiceboxSdkFfi $(PODS_TARGET_SRCROOT)/target/${CARGO_BUILD_TARGET}/release/include',
      'SWIFT_INCLUDE_PATHS' => '$(HEADER_SEARCH_PATHS)',

      'OTHER_LDFLAGS' => '$(PODS_TARGET_SRCROOT)/target/$(CARGO_BUILD_TARGET)/release/libjuicebox_sdk_ffi.a',

      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=arm64]' => 'aarch64-apple-ios-sim',
      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=*]' => 'x86_64-apple-ios',
      'CARGO_BUILD_TARGET[sdk=iphoneos*]' => 'aarch64-apple-ios',

      'ARCHS[sdk=iphonesimulator*]' => 'x86_64 arm64',
      'ARCHS[sdk=iphoneos*]' => 'arm64',
  }

  s.prepare_command = %Q(
    set -euo pipefail
    CARGO_BUILD_TARGET=aarch64-apple-ios swift/ffi.sh --release
    CARGO_BUILD_TARGET=x86_64-apple-ios swift/ffi.sh --release
    CARGO_BUILD_TARGET=aarch64-apple-ios-sim swift/ffi.sh --release
  )
end
