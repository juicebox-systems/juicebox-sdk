Pod::Spec.new do |s|
  s.name             = 'JuiceboxSdk'
  s.license          = 'MIT'
  s.author           = { 'Nora Trapp' => 'nora@juicebox.me' }
  s.version          = '0.3.0'
  s.summary          = 'A Swift wrapper library for interfacing with the Juicebox service.'

  s.homepage         = 'https://github.com/juicebox-systems/juicebox-sdk'
  s.source           = { :git => 'https://github.com/juicebox-systems/juicebox-sdk.git', :tag => "#{s.version}", :submodules => true }

  s.swift_version    = '5'
  s.platform         = :ios, '13'

  s.source_files = ['swift/Sources/**/*.swift']
  s.preserve_paths = [
    'artifacts/ffi',
    'swift/Sources/JuiceboxSdkFfi',
  ]

  s.pod_target_xcconfig = {
      'HEADER_SEARCH_PATHS' => '$(PODS_TARGET_SRCROOT)/swift/Sources/JuiceboxSdkFfi',
      'SWIFT_INCLUDE_PATHS' => '$(HEADER_SEARCH_PATHS)',

      'OTHER_LDFLAGS' => '$(PODS_TARGET_SRCROOT)/artifacts/ffi/$(CARGO_BUILD_TARGET)/libjuicebox_sdk_ffi.a',

      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=arm64]' => 'aarch64-apple-ios-sim',
      'CARGO_BUILD_TARGET[sdk=iphonesimulator*][arch=*]' => 'x86_64-apple-ios',
      'CARGO_BUILD_TARGET[sdk=iphoneos*]' => 'aarch64-apple-ios',

      'ARCHS[sdk=iphonesimulator*]' => 'x86_64 arm64',
      'ARCHS[sdk=iphoneos*]' => 'arm64',
  }
end
