// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NoiseProtocol",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .watchOS(.v9),
        .tvOS(.v16)
    ],
    products: [
        .library(
            name: "NoiseProtocol",
            targets: ["NoiseProtocol"]
        )
    ],
    targets: [
        .target(
            name: "NoiseProtocol",
            path: "Sources/NoiseProtocol"
        ),
        .testTarget(
            name: "NoiseProtocolTests",
            dependencies: ["NoiseProtocol"],
            path: "Tests/NoiseProtocolTests"
        )
    ]
)
