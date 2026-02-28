# Noise Protocol Library (Android + iOS)

Cross-platform Noise Protocol implementation with native Kotlin and Swift APIs.

Current scope:
- Handshake patterns: `NN`, `NK`, `KK`, `IK`, `XX`
- Core state machines: `CipherState`, `SymmetricState`, `HandshakeState`
- Pluggable crypto adapters
- Shared test-vector harness and Android/iOS interop checks

## Repository layout

- `android/`: Kotlin/JVM modules
  - `:noise-core`
  - `:noise-crypto`
  - `:noise-testing`
- `ios/`: Swift Package
  - `NoiseCore`
  - `NoiseCryptoAdapters`
  - `NoiseTestHarness`
- `test-vectors/`: shared schema and fixtures

## Android usage (Kotlin)

### 1) Add modules

Use this repository as a source dependency and depend on:
- `:noise-core`
- `:noise-crypto`

Example (`settings.gradle.kts` in your app project):

```kotlin
includeBuild("../noise-protocol/android")
```

Example (`build.gradle.kts` in your module):

```kotlin
dependencies {
    implementation("dev.noiseprotocol:noise-core:0.1.0-SNAPSHOT")
    implementation("dev.noiseprotocol:noise-crypto:0.1.0-SNAPSHOT")
}
```

### 2) Build a crypto suite

```kotlin
import dev.noiseprotocol.crypto.CryptoProvider
import dev.noiseprotocol.crypto.NoiseAeadAlgorithm
import dev.noiseprotocol.crypto.NoiseCryptoAlgorithms
import dev.noiseprotocol.crypto.NoiseDhAlgorithm
import dev.noiseprotocol.crypto.NoiseHashAlgorithm

val provider = CryptoProvider()
val suite = provider.createSuite(
    NoiseCryptoAlgorithms(
        dh = NoiseDhAlgorithm.X25519,
        aead = NoiseAeadAlgorithm.CHACHA20_POLY1305,
        hash = NoiseHashAlgorithm.SHA256
    )
)
```

### 3) Run a handshake (NN example)

```kotlin
import dev.noiseprotocol.core.HandshakePattern
import dev.noiseprotocol.core.HandshakeRole
import dev.noiseprotocol.core.HandshakeState

val initiator = HandshakeState.initialize(
    pattern = HandshakePattern.NN,
    role = HandshakeRole.INITIATOR,
    cryptoSuite = suite,
    protocolName = "Noise_NN_25519_ChaChaPoly_SHA256"
)
val responder = HandshakeState.initialize(
    pattern = HandshakePattern.NN,
    role = HandshakeRole.RESPONDER,
    cryptoSuite = suite,
    protocolName = "Noise_NN_25519_ChaChaPoly_SHA256"
)

val m1 = initiator.writeMessage("hello".encodeToByteArray())
val r1 = responder.readMessage(m1)

val m2 = responder.writeMessage("world".encodeToByteArray())
val r2 = initiator.readMessage(m2)

check(String(r1) == "hello")
check(String(r2) == "world")
check(initiator.isComplete() && responder.isComplete())

val (tx, rx) = initiator.splitTransportStates()
```

For `NK`, `KK`, `IK`, and `XX`, provide required static key material in `HandshakeState.initialize(...)`.

## iOS usage (Swift)

### 1) Add package

Add this repository as a Swift Package dependency and link:
- `NoiseCore`
- `NoiseCryptoAdapters`

Example (`Package.swift`):
- Add `.package(path: "../noise-protocol/ios")` (or the repository URL) to dependencies.
- In your target dependencies, link the package products:
  - `NoiseCore`
  - `NoiseCryptoAdapters`

### 2) Build a crypto provider

```swift
import Foundation
import NoiseCore
import NoiseCryptoAdapters

let registry = NoiseCryptoAdapterRegistry(registeringBuiltIns: true)
let factory = NoiseCryptoAdapterFactory(registry: registry)

let suite = NoiseCryptoSuiteDescriptor(
    protocolName: NoiseProtocolDescriptor(rawValue: "Noise_NN_25519_ChaChaPoly_SHA256"),
    diffieHellman: "25519",
    cipher: "ChaChaPoly",
    hash: "SHA256"
)
let provider = try await factory.makeProvider(for: suite)
```

### 3) Run a handshake session (NN example)

```swift
import Foundation
import NoiseCore

let initiatorSession = NoiseHandshakeSession()
let responderSession = NoiseHandshakeSession()

let initiatorConfig = NoiseHandshakeConfiguration(
    protocolName: NoiseProtocolDescriptor(rawValue: "Noise_NN_25519_ChaChaPoly_SHA256"),
    isInitiator: true,
    handshakePattern: .nn
)
let responderConfig = NoiseHandshakeConfiguration(
    protocolName: NoiseProtocolDescriptor(rawValue: "Noise_NN_25519_ChaChaPoly_SHA256"),
    isInitiator: false,
    handshakePattern: .nn
)

try await initiatorSession.initialize(with: initiatorConfig, cryptoProvider: provider)
try await responderSession.initialize(with: responderConfig, cryptoProvider: provider)

let m1 = try await initiatorSession.writeMessage(payload: Data("hello".utf8))
let r1 = try await responderSession.readMessage(m1)

let m2 = try await responderSession.writeMessage(payload: Data("world".utf8))
let r2 = try await initiatorSession.readMessage(m2)

let transport = try await initiatorSession.splitTransportStates()
```

## Verify locally

```bash
# Android
cd android
gradle --no-daemon --console=plain :noise-core:test :noise-crypto:test :noise-testing:test

# iOS
cd ios
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
