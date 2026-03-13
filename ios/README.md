# NoiseProtocol — Swift

A pure-Swift implementation of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html) (revision 34). Zero external dependencies — all cryptography uses Apple CryptoKit.

## Cipher Suite

`Noise_*_25519_ChaChaPoly_SHA256`

| Primitive | Implementation |
|-----------|---------------|
| DH | X25519 via `Curve25519.KeyAgreement` |
| AEAD | ChaCha20-Poly1305 via `ChaChaPoly` |
| Hash | SHA-256 / HMAC / HKDF via `SHA256`, `HMAC<SHA256>` |

## Supported Patterns

| Category | Patterns |
|----------|----------|
| One-way | N, K, X |
| Fundamental | NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX |
| Deferred | NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X, KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1 |
| PSK | Any pattern + psk0–pskN modifier, plus named NKpsk0, IKpsk2 |
| Fallback | XXfallback |

## Platform Requirements

- iOS 16+, macOS 13+, watchOS 9+, tvOS 16+
- Swift 6.0+

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/trancee/noise-protocol.git", from: "2.0.0")
]
```

Or in Xcode: **File → Add Package Dependencies** and point to this directory.

## Quick Start

### NN Handshake (No Authentication)

```swift
import NoiseProtocol

// Initiator
let initiator = try HandshakeState(
    pattern: .NN,
    initiator: true,
    prologue: Data()
)

// Responder
let responder = try HandshakeState(
    pattern: .NN,
    initiator: false,
    prologue: Data()
)

// Message 1: initiator → responder
let (msg1, _) = try initiator.writeMessage(payload: "hello".data(using: .utf8)!)
let (payload1, _) = try responder.readMessage(msg1)

// Message 2: responder → initiator (completes handshake)
let (msg2, respTransport) = try responder.writeMessage(payload: "world".data(using: .utf8)!)
let (payload2, initTransport) = try initiator.readMessage(msg2)

// Transport phase — encrypted bidirectional channel
let ciphertext = try initTransport!.sendCipher.encryptWithAd(Data(), "secret".data(using: .utf8)!)
let plaintext = try respTransport!.receiveCipher.decryptWithAd(Data(), ciphertext)
```

### XX Handshake (Mutual Authentication)

```swift
let initiator = try HandshakeState(
    pattern: .XX,
    initiator: true,
    prologue: Data(),
    s: NoiseKeyPair()  // generate static key
)

let responder = try HandshakeState(
    pattern: .XX,
    initiator: false,
    prologue: Data(),
    s: NoiseKeyPair()
)

let (msg1, _) = try initiator.writeMessage()
let _ = try responder.readMessage(msg1)

let (msg2, _) = try responder.writeMessage()
let _ = try initiator.readMessage(msg2)

let (msg3, respTransport) = try initiator.writeMessage()
let (_, initTransport) = try responder.readMessage(msg3)

// Both sides now have authenticated transport + remote static keys
let remoteKey = initTransport!.remoteStaticKey  // initiator's static public key
```

### IK Handshake (Zero-RTT with Known Responder Key)

```swift
let responderKeyPair = NoiseKeyPair()

let initiator = try HandshakeState(
    pattern: .IK,
    initiator: true,
    prologue: Data(),
    s: NoiseKeyPair(),
    rs: responderKeyPair.publicKey  // known ahead of time
)

let responder = try HandshakeState(
    pattern: .IK,
    initiator: false,
    prologue: Data(),
    s: responderKeyPair
)

// 2-message handshake with encrypted payload in message 1
let (msg1, _) = try initiator.writeMessage(payload: earlyData)
let (decrypted, _) = try responder.readMessage(msg1)

let (msg2, respTransport) = try responder.writeMessage()
let (_, initTransport) = try initiator.readMessage(msg2)
```

### PSK Mode

```swift
let psk = Data(repeating: 0x42, count: 32)  // 32-byte pre-shared key

let initiator = try HandshakeState(
    pattern: .NKpsk0,
    initiator: true,
    prologue: Data(),
    rs: responderPublicKey,
    psks: [psk]
)
```

### XXfallback (IK → XX Downgrade)

```swift
// 1. Initiator tries IK with (possibly wrong) responder key
let ikInitiator = try HandshakeState(
    pattern: .IK, initiator: true, prologue: prologue,
    s: initKeyPair, rs: possiblyWrongKey
)
let (ikMsg1, _) = try ikInitiator.writeMessage(payload: payload)

// 2. Responder can't decrypt → extract ephemeral and fall back to XX
let ephemeral = ikMsg1.prefix(32)

let fallbackInitiator = try HandshakeState(
    pattern: .XXfallback, initiator: true, prologue: prologue,
    s: respKeyPair, re: ephemeral
)
let fallbackResponder = try HandshakeState(
    pattern: .XXfallback, initiator: false, prologue: prologue,
    s: initKeyPair, e: initEphemeralKeyPair
)

// Continue with 2-message XXfallback handshake...
```

## API Reference

### HandshakeState

```swift
// Initialize
HandshakeState(
    pattern: HandshakePattern,  // .NN, .XX, .IK, etc.
    initiator: Bool,
    prologue: Data = Data(),
    s: NoiseKeyPair? = nil,     // local static key pair
    e: NoiseKeyPair? = nil,     // local ephemeral (testing only)
    rs: Data? = nil,            // remote static public key
    re: Data? = nil,            // remote ephemeral (fallback only)
    psks: [Data] = [],
    keyPairGenerator: KeyPairGenerator = DefaultKeyPairGenerator()
)

// Send a handshake message
func writeMessage(payload: Data = Data()) throws -> (Data, TransportState?)

// Receive a handshake message
func readMessage(_ message: Data) throws -> (Data, TransportState?)

// Check whose turn it is
var isMySend: Bool { get }
```

### TransportState

Returned when the handshake completes:

```swift
struct TransportState {
    let sendCipher: CipherState      // encrypt outgoing messages
    let receiveCipher: CipherState   // decrypt incoming messages
    let handshakeHash: Data          // for channel binding
    let remoteStaticKey: Data?       // peer's authenticated static key
}
```

### CipherState

```swift
func encryptWithAd(_ ad: Data, _ plaintext: Data) throws -> Data
func decryptWithAd(_ ad: Data, _ ciphertext: Data) throws -> Data
func rekey()
var hasKey: Bool { get }
```

### HandshakePattern

```swift
HandshakePattern.NN         // static access
HandshakePattern.named("XX") // dynamic lookup (throws on unknown)
HandshakePattern.all         // [String: HandshakePattern] dictionary
```

### Error Handling

All errors are `NoiseError` enum cases:

| Error | Description |
|-------|-------------|
| `.decryptionFailed` | AEAD authentication tag mismatch |
| `.handshakeAlreadyComplete` | Attempted handshake operation after completion |
| `.notYourTurn` | Called write on a read turn or vice versa |
| `.invalidMessage` | Handshake message truncated or malformed |
| `.unknownPattern(name)` | Unknown pattern name in `HandshakePattern.named()` |
| `.missingKey(detail)` | Required key not provided |
| `.nonceExhausted` | Nonce counter overflow (2^64 messages) |

## Testing

```bash
cd ios && swift test
```

34 tests total: 7 test vector tests (validated against cacophony/noise-c canonical vectors) + 27 unit tests covering round-trips, error handling, crypto primitives, pattern definitions, and channel binding.

## Architecture

```
Sources/NoiseProtocol/
├── NoiseError.swift              # Error enum
├── Crypto/
│   ├── DH.swift                  # X25519 key pairs + DH
│   ├── Cipher.swift              # ChaCha20-Poly1305 AEAD
│   └── Hash.swift                # SHA-256, HMAC-SHA256, HKDF
├── State/
│   ├── CipherState.swift         # AEAD + nonce tracking
│   ├── SymmetricState.swift      # Chaining key + handshake hash
│   └── HandshakeState.swift      # Full handshake state machine
└── Pattern/
    └── HandshakePattern.swift    # All pattern definitions
```
