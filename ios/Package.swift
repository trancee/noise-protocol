// swift-tools-version: 6.1
import PackageDescription

let packageSwiftSettings: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
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
        .executable(name: "NoiseVectorConverterCLI", targets: ["NoiseVectorConverterCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/attaswift/BigInt.git", exact: "5.7.0"),
    ],
    targets: [
        .target(
            name: "NoiseCore",
            swiftSettings: packageSwiftSettings
        ),
        .target(
            name: "NoiseCryptoAdapters",
            dependencies: [
                "NoiseCore",
                .product(name: "BigInt", package: "BigInt"),
            ],
            swiftSettings: packageSwiftSettings
        ),
        .target(
            name: "NoiseTestHarness",
            dependencies: ["NoiseCore", "NoiseCryptoAdapters"],
            swiftSettings: packageSwiftSettings
        ),
        .executableTarget(
            name: "NoiseVectorConverterCLI",
            dependencies: ["NoiseTestHarness"],
            swiftSettings: packageSwiftSettings
        ),
        .testTarget(
            name: "NoiseCoreTests",
            dependencies: ["NoiseCore", "NoiseCryptoAdapters"],
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
