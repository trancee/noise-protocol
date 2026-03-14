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
    dependencies: [
        .package(url: "https://github.com/trancee/blake-hash.git", from: "1.1.0")
    ],
    targets: [
        .target(
            name: "NoiseProtocol",
            dependencies: [.product(name: "BlakeHash", package: "blake-hash")],
            path: "Sources/NoiseProtocol"
        ),
        .testTarget(
            name: "NoiseProtocolTests",
            dependencies: ["NoiseProtocol"],
            path: "Tests/NoiseProtocolTests"
        )
    ]
)
