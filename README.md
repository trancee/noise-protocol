# Noise Protocol Library (Android + iOS)

Feature-complete implementations of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html) (revision 34) for **iOS** and **Android**, with zero external dependencies.

## What is Noise?

Noise is a framework for building crypto protocols based on Diffie-Hellman key agreement. It's used in WireGuard, WhatsApp, Lightning Network, and many other systems. Noise provides:

- **Mutual authentication** — both parties prove identity
- **Forward secrecy** — compromised long-term keys don't reveal past sessions
- **Zero-RTT encryption** — encrypted data in the first message (with some patterns)
- **Identity hiding** — static keys encrypted during handshake

## Project Structure

```
noise-protocol/
├── ios/                    # Swift library (CryptoKit)
│   ├── Sources/NoiseProtocol/
│   ├── Tests/
│   ├── Package.swift
│   └── README.md           # Swift API docs & examples
├── android/                # Kotlin library (JCA/JCE)
│   ├── lib/src/main/kotlin/com/noise/protocol/
│   ├── lib/src/test/kotlin/com/noise/protocol/
│   └── README.md           # Kotlin API docs & examples
└── VERSION                 # Canonical version source
```

## Cipher Suite

Both platforms implement `Noise_*_25519_ChaChaPoly_SHA256`:

| Primitive | Algorithm |
|-----------|-----------|
| Key exchange | X25519 |
| Encryption | ChaCha20-Poly1305 |
| Hashing | SHA-256 + HMAC-SHA256 + HKDF |

## Supported Patterns

**38+ patterns** including all one-way, fundamental, deferred, PSK, and fallback:

| Category | Patterns |
|----------|----------|
| One-way | N, K, X |
| Fundamental | NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX |
| Deferred | NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X, KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1 |
| PSK | psk0-pskN modifier, NKpsk0, IKpsk2 |
| Fallback | XXfallback |

## Quick Start

### Swift

```swift
import NoiseProtocol

// XX handshake - mutual authentication, no prior key knowledge
let initiator = try HandshakeState(pattern: .XX, initiator: true, s: NoiseKeyPair())
let responder = try HandshakeState(pattern: .XX, initiator: false, s: NoiseKeyPair())

let (msg1, _) = try initiator.writeMessage()
let _ = try responder.readMessage(msg1)
let (msg2, _) = try responder.writeMessage()
let _ = try initiator.readMessage(msg2)
let (msg3, respTransport) = try initiator.writeMessage()
let (_, initTransport) = try responder.readMessage(msg3)

// Encrypted transport
let ct = try respTransport!.sendCipher.encryptWithAd(Data(), "hello".data(using: .utf8)!)
let pt = try initTransport!.receiveCipher.decryptWithAd(Data(), ct)
```

### Kotlin

```kotlin
import com.noise.protocol.crypto.NoiseKeyPair
import com.noise.protocol.pattern.HandshakePattern
import com.noise.protocol.state.HandshakeState

val initiator = HandshakeState(
    pattern = HandshakePattern.XX, initiator = true, s = NoiseKeyPair.generate()
)
val responder = HandshakeState(
    pattern = HandshakePattern.XX, initiator = false, s = NoiseKeyPair.generate()
)

val (msg1, _) = initiator.writeMessage()
responder.readMessage(msg1)
val (msg2, _) = responder.writeMessage()
initiator.readMessage(msg2)
val (msg3, respTransport) = initiator.writeMessage()
val (_, initTransport) = responder.readMessage(msg3)

// Encrypted transport
val ct = respTransport!!.sendCipher.encryptWithAd(ByteArray(0), "hello".toByteArray())
val pt = initTransport!!.receiveCipher.decryptWithAd(ByteArray(0), ct)
```

## Choosing a Pattern

| Need | Pattern | Messages |
|------|---------|----------|
| No authentication | NN | 2 |
| Responder key known, no initiator auth | NK | 2 |
| Mutual auth, no prior keys | XX | 3 |
| Mutual auth, responder key known (0-RTT) | IK | 2 |
| Pre-shared key + responder key known | NKpsk0 | 2 |
| IK with fallback on wrong key | XXfallback | 2 (after failed IK) |

See the [Noise spec](https://noiseprotocol.org/noise.html#handshake-pattern-basics) for full pattern descriptions and security properties.

## Platform Requirements

| Platform | Minimum | Crypto Backend |
|----------|---------|----------------|
| iOS | 16.0 | Apple CryptoKit |
| macOS | 13.0 | Apple CryptoKit |
| watchOS | 9.0 | Apple CryptoKit |
| tvOS | 16.0 | Apple CryptoKit |
| JVM | Java 11+ | JCA/JCE (native) |

## Installation

### Swift (SPM)

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/trancee/noise-protocol.git", from: "2.0.0")
]
```

### Kotlin (Gradle)

```kotlin
dependencies {
    implementation(project(":lib"))
}
```

## Running Tests

```bash
# iOS - 34 tests (7 test vector + 27 unit)
cd ios && swift test

# Android - 37 tests (7 test vector + 30 unit)
cd android && ./gradlew test
```

All test vectors validated against [cacophony](https://github.com/haskell-cryptography/cacophony) and [noise-c](https://github.com/rweather/noise-c) canonical outputs.

## Design Principles

- **Zero dependencies** — only platform-native crypto APIs
- **Spec conformance** — Noise Protocol Framework revision 34
- **Feature parity** — identical behavior and API shape across platforms
- **Testability** — injectable key generation for deterministic test vectors
- **Type safety** — sealed error hierarchies with exhaustive handling

## Documentation

- [`ios/README.md`](ios/README.md) — Swift API reference, usage examples, architecture
- [`android/README.md`](android/README.md) — Kotlin API reference, usage examples, architecture
- [`CHANGELOG.md`](CHANGELOG.md) — Version history

## License

See [LICENSE](LICENSE) for details.
