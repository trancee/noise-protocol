# NoiseProtocol — Kotlin/JVM

A pure-Kotlin implementation of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html) (revision 34). Zero external dependencies — all cryptography uses native Java Cryptography Architecture (JCA/JCE).

## Cipher Suite

`Noise_*_25519_ChaChaPoly_SHA256`

| Primitive | Implementation |
|-----------|---------------|
| DH | X25519 via JCA `XDH` / `NamedParameterSpec.X25519` |
| AEAD | ChaCha20-Poly1305 via `javax.crypto.Cipher` |
| Hash | SHA-256 / HMAC-SHA256 via `MessageDigest`, `Mac` |

Requires **Java 11+** (for XDH support). Tested with Java 21.

## Supported Patterns

| Category | Patterns |
|----------|----------|
| One-way | N, K, X |
| Fundamental | NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX |
| Deferred | NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1, K1N, K1K, KK1, K1K1, K1X, KX1, K1X1, I1N, I1K, IK1, I1K1, I1X, IX1, I1X1 |
| PSK | Any pattern + psk0–pskN modifier, plus named NKpsk0, IKpsk2 |
| Fallback | XXfallback |

## Installation

### Gradle (Kotlin DSL)

Add the library module as a dependency:

```kotlin
dependencies {
    implementation(project(":lib"))
}
```

Or publish to a local Maven repository and consume as a regular dependency.

## Quick Start

### NN Handshake (No Authentication)

```kotlin
import com.noise.protocol.pattern.HandshakePattern
import com.noise.protocol.state.HandshakeState

val initiator = HandshakeState(
    pattern = HandshakePattern.NN,
    initiator = true,
    prologue = ByteArray(0)
)

val responder = HandshakeState(
    pattern = HandshakePattern.NN,
    initiator = false,
    prologue = ByteArray(0)
)

// Message 1: initiator → responder
val (msg1, _) = initiator.writeMessage("hello".toByteArray())
val (payload1, _) = responder.readMessage(msg1)

// Message 2: responder → initiator (completes handshake)
val (msg2, respTransport) = responder.writeMessage("world".toByteArray())
val (payload2, initTransport) = initiator.readMessage(msg2)

// Transport phase — encrypted bidirectional channel
val ct = initTransport!!.sendCipher.encryptWithAd(ByteArray(0), "secret".toByteArray())
val pt = respTransport!!.receiveCipher.decryptWithAd(ByteArray(0), ct)
```

### XX Handshake (Mutual Authentication)

```kotlin
import com.noise.protocol.crypto.NoiseKeyPair

val initiator = HandshakeState(
    pattern = HandshakePattern.XX,
    initiator = true,
    prologue = ByteArray(0),
    s = NoiseKeyPair.generate()
)

val responder = HandshakeState(
    pattern = HandshakePattern.XX,
    initiator = false,
    prologue = ByteArray(0),
    s = NoiseKeyPair.generate()
)

val (msg1, _) = initiator.writeMessage()
responder.readMessage(msg1)

val (msg2, _) = responder.writeMessage()
initiator.readMessage(msg2)

val (msg3, respTransport) = initiator.writeMessage()
val (_, initTransport) = responder.readMessage(msg3)

// Both sides now have authenticated transport + remote static keys
val remoteKey = initTransport!!.remoteStaticKey
```

### IK Handshake (Zero-RTT with Known Responder Key)

```kotlin
val responderKeyPair = NoiseKeyPair.generate()

val initiator = HandshakeState(
    pattern = HandshakePattern.IK,
    initiator = true,
    prologue = ByteArray(0),
    s = NoiseKeyPair.generate(),
    rs = responderKeyPair.publicKey
)

val responder = HandshakeState(
    pattern = HandshakePattern.IK,
    initiator = false,
    prologue = ByteArray(0),
    s = responderKeyPair
)

// 2-message handshake with encrypted payload in message 1
val (msg1, _) = initiator.writeMessage(earlyData)
val (decrypted, _) = responder.readMessage(msg1)

val (msg2, respTransport) = responder.writeMessage()
val (_, initTransport) = initiator.readMessage(msg2)
```

### PSK Mode

```kotlin
val psk = ByteArray(32) { 0x42 }  // 32-byte pre-shared key

val initiator = HandshakeState(
    pattern = HandshakePattern.NKpsk0,
    initiator = true,
    prologue = ByteArray(0),
    rs = responderPublicKey,
    psks = listOf(psk)
)
```

### XXfallback (IK → XX Downgrade)

```kotlin
// 1. Initiator tries IK with (possibly wrong) responder key
val ikInitiator = HandshakeState(
    pattern = HandshakePattern.IK, initiator = true, prologue = prologue,
    s = initKeyPair, rs = possiblyWrongKey
)
val (ikMsg1, _) = ikInitiator.writeMessage(payload)

// 2. Responder can't decrypt → extract ephemeral and fall back to XX
val ephemeral = ikMsg1.copyOfRange(0, 32)

val fallbackInitiator = HandshakeState(
    pattern = HandshakePattern.XXfallback, initiator = true, prologue = prologue,
    s = respKeyPair, re = ephemeral
)
val fallbackResponder = HandshakeState(
    pattern = HandshakePattern.XXfallback, initiator = false, prologue = prologue,
    s = initKeyPair, e = initEphemeralKeyPair
)

// Continue with 2-message XXfallback handshake...
```

## API Reference

### HandshakeState

```kotlin
// Initialize
HandshakeState(
    pattern: HandshakePattern,   // HandshakePattern.NN, .XX, .IK, etc.
    initiator: Boolean,
    prologue: ByteArray = ByteArray(0),
    s: NoiseKeyPair? = null,     // local static key pair
    e: NoiseKeyPair? = null,     // local ephemeral (testing only)
    rs: ByteArray? = null,       // remote static public key
    re: ByteArray? = null,       // remote ephemeral (fallback only)
    psks: List<ByteArray> = emptyList(),
    keyPairGenerator: NoiseKeyPairGenerator = RandomKeyPairGenerator()
)

// Send a handshake message
fun writeMessage(payload: ByteArray = ByteArray(0)): Pair<ByteArray, TransportState?>

// Receive a handshake message
fun readMessage(message: ByteArray): Pair<ByteArray, TransportState?>

// Check whose turn it is
val isMySend: Boolean
```

### TransportState

Returned when the handshake completes:

```kotlin
data class TransportState(
    val sendCipher: CipherState,      // encrypt outgoing messages
    val receiveCipher: CipherState,   // decrypt incoming messages
    val handshakeHash: ByteArray,     // for channel binding
    val remoteStaticKey: ByteArray?   // peer's authenticated static key
)
```

### CipherState

```kotlin
fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray
fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray
fun rekey()
val hasKey: Boolean
```

### HandshakePattern

```kotlin
HandshakePattern.NN          // static access
HandshakePattern.named("XX") // dynamic lookup (throws on unknown)
HandshakePattern.all          // Map<String, HandshakePattern>
```

### Error Handling

All errors extend the sealed `NoiseException` class:

| Exception | Description |
|-----------|-------------|
| `DecryptionFailed` | AEAD authentication tag mismatch |
| `HandshakeAlreadyComplete` | Attempted handshake operation after completion |
| `NotYourTurn` | Called write on a read turn or vice versa |
| `InvalidMessage` | Handshake message truncated or malformed |
| `UnknownPattern` | Unknown pattern name in `HandshakePattern.named()` |
| `MissingKey` | Required key not provided |
| `NonceExhausted` | Nonce counter overflow (2^64 messages) |

## Testing

```bash
cd android && ./gradlew test
```

37 tests total: 7 test vector tests (validated against cacophony/noise-c canonical vectors) + 30 unit tests covering round-trips, error handling, crypto primitives, pattern definitions, and channel binding.

## Architecture

```
lib/src/main/kotlin/com/noise/protocol/
├── NoiseException.kt             # Sealed exception hierarchy
├── crypto/
│   ├── DH.kt                    # X25519 key pairs + DH via JCA
│   ├── Cipher.kt                # ChaCha20-Poly1305 AEAD
│   └── Hash.kt                  # SHA-256, HMAC-SHA256, HKDF
├── state/
│   ├── CipherState.kt           # AEAD + nonce tracking
│   ├── SymmetricState.kt        # Chaining key + handshake hash
│   └── HandshakeState.kt        # Full handshake state machine
└── pattern/
    └── HandshakePattern.kt      # All pattern definitions
```
