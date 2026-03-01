# Noise Protocol Library (Android + iOS)

Cross-platform Noise Protocol implementation with native Kotlin and Swift APIs.

[The Noise Protocol Framework](https://noiseprotocol.org/noise.html)
```
Revision: 34
Date: 2018-07-11
```

Current scope:
- Handshake patterns: `NN`, `NK`, `KK`, `IK`, `XX`
- Core state machines: `CipherState`, `SymmetricState`, `HandshakeState`
- Pluggable crypto adapters
- Shared test-vector harness and Android/iOS interop checks

## Repository layout

- `android/`: Kotlin/JVM + Android library modules
  - `:noise-core`
  - `:noise-crypto`
  - `:noise-testing`
  - `:noise-android-aar` (publishable AAR wrapper)
  - source/test package directories follow `noise/protocol/...`
- `Package.swift`: canonical Swift Package entrypoint for repository/tag-based consumption
- `ios/`: Swift sources/tests (with compatibility `ios/Package.swift` manifest)
  - `NoiseCore`
  - `NoiseCryptoAdapters`
  - `NoiseTestHarness`
- `test-vectors/`: shared schema and fixtures
  - `fixtures/v1/` contains a full handshake/suite coverage matrix (80 vectors):
    `NN|NK|KK|IK|XX` × `25519|448` × `ChaChaPoly|AESGCM` × `SHA256|SHA512|BLAKE2s|BLAKE2b`

## GitHub releases

- Workflow: `.github/workflows/release.yml`
- Full operator runbook: `RELEASE.md`
- Canonical version contract:
  - `VERSION` is the single source of truth for Android, iOS, and release automation.
  - Release tags must match `v<VERSION>` and are validated by:
    - `bash ./scripts/verify-version-parity.sh` (CI)
    - `bash ./scripts/verify-version-parity.sh <tag>` (release)
- Trigger:
  - push a tag matching `v*` (for example `v0.1.0`)
  - manual dispatch with a `tag` input
- Publish targets:
  - GitHub Packages Maven artifact: `noise.protocol:noise-android-aar:<VERSION>`
    - Task: `:noise-android-aar:publishReleasePublicationToGitHubPackagesRepository`
  - External Maven repository artifact: `noise.protocol:noise-android-aar:<VERSION>`
    - Task: `:noise-android-aar:publishReleasePublicationToExternalMavenRepository`
    - Secrets: `MAVEN_REPOSITORY_URL`, `MAVEN_REPOSITORY_USERNAME`, `MAVEN_REPOSITORY_PASSWORD`
    - If any secret is missing, the workflow skips external Maven upload.
- Published GitHub release assets:
  - `noise-android-<tag>.tar.gz` (Android `noise-core`, `noise-crypto`, `noise-testing` JARs)
  - `noise-android-aar-<tag>.aar` (Android AAR artifact for direct consumption)
  - `noise-ios-swiftpm-<tag>.tar.gz` (Swift Package manifest + Sources + `VERSION`)
  - `SHA256SUMS.txt`

## Android usage (Kotlin)

### 1) Add dependency

Published Android artifact (`noise-android-aar`) is uploaded by release workflow to GitHub Packages and the configured external Maven repository.

Example (`build.gradle.kts` in your app project):

```kotlin
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/<owner>/<repo>")
        credentials {
            username = (findProperty("gpr.user") as String?) ?: System.getenv("GITHUB_ACTOR")
            password = (findProperty("gpr.key") as String?) ?: System.getenv("GITHUB_TOKEN")
        }
    }
}

dependencies {
    implementation("noise.protocol:noise-android-aar:<VERSION>")
}
```

For local source development, include this repository build:

```kotlin
includeBuild("../noise-protocol/android")
```

### 2) Build the default Noise configuration

```kotlin
import noise.protocol.crypto.CryptoProvider

val provider = CryptoProvider()
val defaultConfig = provider.createDefaultConfiguration()
val suite = defaultConfig.suite
// defaultConfig.pattern == HandshakePattern.XX
// defaultConfig.protocolName == "Noise_XX_25519_AESGCM_SHA256"
```

### 3) Run a handshake (default XX profile)

```kotlin
import noise.protocol.core.HandshakeRole
import noise.protocol.core.HandshakeState

val initiatorStatic = suite.diffieHellman.generateKeyPair()
val responderStatic = suite.diffieHellman.generateKeyPair()

val initiator = HandshakeState.initialize(
    pattern = defaultConfig.pattern,
    role = HandshakeRole.INITIATOR,
    cryptoSuite = suite,
    protocolName = defaultConfig.protocolName,
    localStatic = initiatorStatic,
    remoteStatic = responderStatic.publicKey
)
val responder = HandshakeState.initialize(
    pattern = defaultConfig.pattern,
    role = HandshakeRole.RESPONDER,
    cryptoSuite = suite,
    protocolName = defaultConfig.protocolName,
    localStatic = responderStatic,
    remoteStatic = initiatorStatic.publicKey
)

val m1 = initiator.writeMessage("hello".encodeToByteArray())
responder.readMessage(m1)

val m2 = responder.writeMessage("world".encodeToByteArray())
initiator.readMessage(m2)

val m3 = initiator.writeMessage("done".encodeToByteArray())
responder.readMessage(m3)

check(initiator.isComplete() && responder.isComplete())

val (tx, rx) = initiator.splitTransportStates()
```

### 4) Use a different crypto suite

```kotlin
import noise.protocol.core.HandshakePattern
import noise.protocol.crypto.NoiseAeadAlgorithm
import noise.protocol.crypto.NoiseCryptoAlgorithms
import noise.protocol.crypto.NoiseDhAlgorithm
import noise.protocol.crypto.NoiseHashAlgorithm

val customAlgorithms = NoiseCryptoAlgorithms(
    dh = NoiseDhAlgorithm.X25519,
    aead = NoiseAeadAlgorithm.CHACHA20_POLY1305,
    hash = NoiseHashAlgorithm.SHA512
)
val customSuite = provider.createSuite(customAlgorithms)
val customPattern = HandshakePattern.XX
val customProtocolName = "Noise_XX_25519_ChaChaPoly_SHA512"
```

Use `customSuite`, `customPattern`, and `customProtocolName` in `HandshakeState.initialize(...)` on both peers.

## iOS usage (Swift)

Requires Swift 6.0 or newer.

### 1) Add package

Add this repository as a Swift Package dependency and link:
- `NoiseCore`
- `NoiseCryptoAdapters`

Example (`Package.swift`):
- Add `.package(path: "../noise-protocol")` for local development, or the repository URL for tag-based usage.
- In your target dependencies, link the package products:
  - `NoiseCore`
  - `NoiseCryptoAdapters`

### 2) Build the default Noise configuration

```swift
import Foundation
import NoiseCore
import NoiseCryptoAdapters

let factory = NoiseCryptoAdapterFactory()
let suite = NoiseCryptoSuiteDescriptor.bootstrapDefault
let provider = try await factory.makeBootstrapDefaultProvider()
```

### 3) Run a handshake session (default XX profile)

```swift
import Foundation
import NoiseCore

let initiatorSession = NoiseHandshakeSession()
let responderSession = NoiseHandshakeSession()
let initiatorStatic = try provider.diffieHellman.generateKeyPair()
let responderStatic = try provider.diffieHellman.generateKeyPair()

let initiatorConfig = NoiseHandshakeConfiguration(
    protocolName: suite.protocolName,
    isInitiator: true,
    handshakePattern: .xx,
    localStaticKey: initiatorStatic,
    remoteStaticKey: responderStatic.publicKey
)
let responderConfig = NoiseHandshakeConfiguration(
    protocolName: suite.protocolName,
    isInitiator: false,
    handshakePattern: .xx,
    localStaticKey: responderStatic,
    remoteStaticKey: initiatorStatic.publicKey
)

try await initiatorSession.initialize(with: initiatorConfig, cryptoProvider: provider)
try await responderSession.initialize(with: responderConfig, cryptoProvider: provider)

let m1 = try await initiatorSession.writeMessage(payload: Data("hello".utf8))
_ = try await responderSession.readMessage(m1)

let m2 = try await responderSession.writeMessage(payload: Data("world".utf8))
_ = try await initiatorSession.readMessage(m2)

let m3 = try await initiatorSession.writeMessage(payload: Data("done".utf8))
_ = try await responderSession.readMessage(m3)

let transport = try await initiatorSession.splitTransportStates()
```

### 4) Use a different crypto suite

```swift
import NoiseCore
import NoiseCryptoAdapters

let customSuite = NoiseCryptoSuiteDescriptor(
    protocolName: NoiseProtocolDescriptor(rawValue: "Noise_XX_25519_ChaChaPoly_SHA512"),
    diffieHellman: "25519",
    cipher: "ChaChaPoly",
    hash: "SHA512"
)
let customProvider = try await factory.makeProvider(for: customSuite)
```

Use `customSuite.protocolName` and `customProvider` when initializing both handshake sessions.

## Verify locally

```bash
# Version contract parity
bash ./scripts/verify-version-parity.sh

# Android
cd android
gradle --no-daemon --console=plain :noise-core:test :noise-crypto:test :noise-testing:test
gradle --no-daemon --console=plain :noise-android-aar:assembleRelease :noise-android-aar:publishReleasePublicationToMavenLocal
cd ..

# iOS (repository-root Swift Package entrypoint)
swift test

# Cross-platform interop
bash ./scripts/verify-cross-platform-interop.sh
```

## Run benchmark-oriented tests

```bash
# Run all benchmark-oriented variations and refresh benchmark results doc
bash ./scripts/run-benchmarks-and-update-doc.sh
```

Policy: always use the script above when running benchmarks so `docs/Benchmark_Test_Results.md` stays current.

## Notes and current limitations

- Android built-in provider supports:
  - DH: `X25519`, `X448`
  - AEAD: `ChaCha20-Poly1305`, `AES-GCM`
  - Hash/HKDF: `SHA-256`, `SHA-512`, `BLAKE2s`, `BLAKE2b`
- iOS built-in registry ships:
  - DH: `25519`
  - Ciphers: `ChaChaPoly`, `AESGCM`
  - Hashes: `SHA256`, `SHA512`

For architecture and internals, see:
- `docs/Noise_Protocol_Core.md`
- `docs/Noise_Crypto_Adapters.md`
- `docs/Noise_Test_Harness.md`
