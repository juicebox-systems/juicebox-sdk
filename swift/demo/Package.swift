// swift-tools-version: 5.7

import PackageDescription

let package = Package(
    name: "demo",
    platforms: [
       .macOS(.v10_15), .iOS(.v13)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.2.2"),
        .package(path: "../../swift")
    ],
    targets: [
        .executableTarget(
            name: "demo",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "JuiceboxSdk", package: "swift")
            ],
            linkerSettings: [.unsafeFlags(["-L../../target/debug/"])])
    ]
)
