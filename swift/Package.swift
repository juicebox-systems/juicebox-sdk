// swift-tools-version:5.2

import PackageDescription

let package = Package(
    name: "JuiceboxSdk",
    platforms: [
       .macOS(.v10_15), .iOS(.v13)
    ],
    products: [
        .library(
            name: "JuiceboxSdk",
            targets: ["JuiceboxSdk"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0")
    ],
    targets: [
        .systemLibrary(name: "JuiceboxSdkFfi"),
        .target(
            name: "JuiceboxSdk",
            dependencies: ["JuiceboxSdkFfi"]
        ),
        .testTarget(
            name: "JuiceboxSdkTests",
            dependencies: ["JuiceboxSdk"],
            linkerSettings: [.unsafeFlags(["-L../target/debug/"])]
        )
    ]
)
