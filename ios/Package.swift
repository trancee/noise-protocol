// swift-tools-version: 6.1
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
            swiftSettings: packageSwiftSettings
        ),
        .target(
            name: "NoiseCryptoAdapters",
            dependencies: ["NoiseCore"],
            swiftSettings: packageSwiftSettings
        ),
        .target(
            name: "NoiseTestHarness",
            dependencies: ["NoiseCore", "NoiseCryptoAdapters"],
            swiftSettings: packageSwiftSettings
        ),
        .testTarget(
            name: "NoiseCoreTests",
            dependencies: ["NoiseCore"],
            swiftSettings: packageSwiftSettings
        ),
        .testTarget(
            name: "NoiseCryptoAdaptersTests",
            dependencies: ["NoiseCryptoAdapters"],
            swiftSettings: packageSwiftSettings
        ),
        .testTarget(
            name: "NoiseTestHarnessTests",
            dependencies: ["NoiseTestHarness", "NoiseCore"],
            swiftSettings: packageSwiftSettings
        ),
    ]
)
