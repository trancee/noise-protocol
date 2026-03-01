// swift-tools-version: 6.0
import PackageDescription

let packageSwiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .unsafeFlags(["-strict-concurrency=complete", "-warnings-as-errors"]),
]

let package = Package(
    name: "NoiseProtocol",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
    ],
    products: [
        .library(name: "NoiseCore", targets: ["NoiseCore"]),
        .library(name: "NoiseCryptoAdapters", targets: ["NoiseCryptoAdapters"]),
        .library(name: "NoiseTestHarness", targets: ["NoiseTestHarness"]),
    ],
    targets: [
        .target(
            name: "NoiseCore",
            path: "ios/Sources/NoiseCore",
            swiftSettings: packageSwiftSettings
        ),
        .target(
            name: "NoiseCryptoAdapters",
            dependencies: ["NoiseCore"],
            path: "ios/Sources/NoiseCryptoAdapters",
            swiftSettings: packageSwiftSettings
        ),
        .target(
            name: "NoiseTestHarness",
            dependencies: ["NoiseCore", "NoiseCryptoAdapters"],
            path: "ios/Sources/NoiseTestHarness",
            swiftSettings: packageSwiftSettings
        ),
        .testTarget(
            name: "NoiseCoreTests",
            dependencies: ["NoiseCore", "NoiseCryptoAdapters"],
            path: "ios/Tests/NoiseCoreTests",
            swiftSettings: packageSwiftSettings
        ),
        .testTarget(
            name: "NoiseCryptoAdaptersTests",
            dependencies: ["NoiseCryptoAdapters"],
            path: "ios/Tests/NoiseCryptoAdaptersTests",
            swiftSettings: packageSwiftSettings
        ),
        .testTarget(
            name: "NoiseTestHarnessTests",
            dependencies: ["NoiseTestHarness", "NoiseCore"],
            path: "ios/Tests/NoiseTestHarnessTests",
            swiftSettings: packageSwiftSettings
        ),
    ]
)
