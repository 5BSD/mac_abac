// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "vLabelTools",
    platforms: [
        .macOS(.v15)  // For development; runs on FreeBSD
    ],
    products: [
        .library(
            name: "VLabel",
            targets: ["VLabel"]
        ),
        .executable(
            name: "vlabelctl",
            targets: ["vlabelctl"]
        ),
    ],
    dependencies: [
        .package(path: "../../FreeBSDKit"),
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.3.0"),
    ],
    targets: [
        // C module for ioctl definitions and wrappers
        .target(
            name: "CVLabel",
            dependencies: [],
            path: "Sources/CVLabel",
            publicHeadersPath: "include"
        ),

        // Swift library wrapping /dev/vlabel
        .target(
            name: "VLabel",
            dependencies: [
                "CVLabel",
                .product(name: "Descriptors", package: "FreeBSDKit"),
                .product(name: "Capsicum", package: "FreeBSDKit"),
                .product(name: "FreeBSDKit", package: "FreeBSDKit"),
            ]
        ),

        // CLI tool
        .executableTarget(
            name: "vlabelctl",
            dependencies: [
                "VLabel",
                .product(name: "FreeBSDKit", package: "FreeBSDKit"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),

        // Tests
        .testTarget(
            name: "VLabelTests",
            dependencies: ["VLabel"]
        ),
    ]
)
