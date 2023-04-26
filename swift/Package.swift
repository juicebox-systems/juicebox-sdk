// swift-tools-version:5.2

import PackageDescription

let package = Package(
    name: "LoamSdk",
    platforms: [
       .macOS(.v10_15), .iOS(.v13)
    ],
    products: [
        .library(
            name: "LoamSdk",
            targets: ["LoamSdk"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0"),
    ],
    targets: [
        .systemLibrary(name: "LoamSdkFfi"),
        .target(
            name: "LoamSdk",
            dependencies: ["LoamSdkFfi"]
        ),
        .testTarget(
            name: "LoamSdkTests",
            dependencies: ["LoamSdk"],
            linkerSettings: [.unsafeFlags(["-L../target/debug/"])]
        )
    ]
)
