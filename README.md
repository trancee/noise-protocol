# Noise Protocol Library (Android + iOS)

Feature-complete implementations of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html) (revision 34) for **iOS** and **Android**, with minimal external dependencies.

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
├── test-vectors/           # Shared cross-platform JSON test vectors (8 cipher suites)
└── VERSION                 # Canonical version source
```

## Cipher Suites

Both platforms support **8 cipher suites** — all combinations of 2 AEAD ciphers × 4 hash functions, with X25519 key exchange:

| Suite Name | Cipher | Hash | HASHLEN |
|------------|--------|------|---------|
| `Noise_25519_ChaChaPoly_SHA256` | ChaCha20-Poly1305 | SHA-256 | 32 |
| `Noise_25519_ChaChaPoly_SHA512` | ChaCha20-Poly1305 | SHA-512 | 64 |
| `Noise_25519_ChaChaPoly_BLAKE2s` | ChaCha20-Poly1305 | BLAKE2s | 32 |
| `Noise_25519_ChaChaPoly_BLAKE2b` | ChaCha20-Poly1305 | BLAKE2b | 64 |
| `Noise_25519_AESGCM_SHA256` | AES-256-GCM | SHA-256 | 32 |
| `Noise_25519_AESGCM_SHA512` | AES-256-GCM | SHA-512 | 64 |
| `Noise_25519_AESGCM_BLAKE2s` | AES-256-GCM | BLAKE2s | 32 |
| `Noise_25519_AESGCM_BLAKE2b` | AES-256-GCM | BLAKE2b | 64 |

The default cipher suite is `Noise_25519_ChaChaPoly_SHA256`. Suites with 64-byte hashes (SHA-512, BLAKE2b) automatically truncate HKDF output to 32 bytes for cipher keys per the Noise spec.

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

// XX handshake with default cipher suite (ChaChaPoly_SHA256)
let initiator = try HandshakeState(pattern: .XX, initiator: true, s: NoiseKeyPair())
let responder = try HandshakeState(pattern: .XX, initiator: false, s: NoiseKeyPair())

let (msg1, _) = try initiator.writeMessage()
let _ = try responder.readMessage(msg1)
let (msg2, _) = try responder.writeMessage()
let _ = try initiator.readMessage(msg2)
let (msg3, initTransport) = try initiator.writeMessage()
let (_, respTransport) = try responder.readMessage(msg3)

// Encrypted transport
let ct = try initTransport!.sendCipher.encryptWithAd(Data(), plaintext: "hello".data(using: .utf8)!)
let pt = try respTransport!.receiveCipher.decryptWithAd(Data(), ciphertext: ct)
```

To use a different cipher suite, pass the `suite` parameter:

```swift
let initiator = try HandshakeState(
    pattern: .XX, initiator: true,
    suite: .noise_25519_AESGCM_SHA512,
    s: NoiseKeyPair()
)
```

### Kotlin

```kotlin
import com.noise.protocol.crypto.CipherSuite
import com.noise.protocol.crypto.NoiseKeyPair
import com.noise.protocol.pattern.HandshakePattern
import com.noise.protocol.state.HandshakeState

// XX handshake with default cipher suite (ChaChaPoly_SHA256)
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
val (msg3, initTransport) = initiator.writeMessage()
val (_, respTransport) = responder.readMessage(msg3)

// Encrypted transport
val ct = initTransport!!.sendCipher.encryptWithAd(ByteArray(0), "hello".toByteArray())
val pt = respTransport!!.receiveCipher.decryptWithAd(ByteArray(0), ct)
```

To use a different cipher suite, pass the `suite` parameter:

```kotlin
val initiator = HandshakeState(
    pattern = HandshakePattern.XX, initiator = true,
    suite = CipherSuite.NOISE_25519_AESGCM_SHA512,
    s = NoiseKeyPair.generate()
)
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
| JVM | Java 21+ | JCA/JCE (native) |

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
# iOS - 36 tests (9 test vector + 27 unit)
cd ios && swift test

# Android - 73 tests (42 parameterized test vector + 1 XXfallback + 30 unit)
cd android && ./gradlew test
```

Test vectors cover 8 cipher suites × 5 base patterns (NN, NK, KK, IK, XX) = 40, plus 2 PSK patterns (NKpsk0, IKpsk2) for ChaChaPoly_SHA256, plus XXfallback — 43 test vectors total. Both platforms validate against [cacophony](https://github.com/haskell-cryptography/cacophony) and [noise-c](https://github.com/rweather/noise-c) canonical outputs using shared JSON fixtures in `test-vectors/`.

## Design Principles

- **Minimal dependencies** — platform-native crypto APIs plus [`blake-hash`](https://github.com/trancee/blake-hash) for BLAKE2
- **Spec conformance** — Noise Protocol Framework revision 34
- **Feature parity** — identical behavior and API shape across platforms
- **Testability** — injectable key generation for deterministic test vectors
- **Type safety** — sealed error hierarchies with exhaustive handling

## Documentation

- [`ios/README.md`](ios/README.md) — Swift API reference, usage examples, architecture
- [`android/README.md`](android/README.md) — Kotlin API reference, usage examples, architecture
- [`BENCHMARK.md`](BENCHMARK.md) — Performance benchmarks for all cipher suites and patterns
- [`CHANGELOG.md`](CHANGELOG.md) — Version history

## License

See [LICENSE](LICENSE) for details.
