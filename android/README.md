# NoiseProtocol — Kotlin/JVM

A Kotlin implementation of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html) (revision 34). Uses native Java Cryptography Architecture (JCA/JCE) for core cryptography and [`blake-hash`](https://github.com/trancee/blake-hash) for BLAKE2 hashing.

## Cipher Suites

**8 cipher suites** — all combinations of 2 AEAD ciphers × 4 hash functions, with X25519 key exchange:

| Constant | Cipher | Hash | HASHLEN | BLOCKLEN |
|----------|--------|------|---------|----------|
| `NOISE_25519_CHACHAPOLY_SHA256` | ChaCha20-Poly1305 | SHA-256 | 32 | 64 |
| `NOISE_25519_CHACHAPOLY_SHA512` | ChaCha20-Poly1305 | SHA-512 | 64 | 128 |
| `NOISE_25519_CHACHAPOLY_BLAKE2S` | ChaCha20-Poly1305 | BLAKE2s | 32 | 64 |
| `NOISE_25519_CHACHAPOLY_BLAKE2B` | ChaCha20-Poly1305 | BLAKE2b | 64 | 128 |
| `NOISE_25519_AESGCM_SHA256` | AES-256-GCM | SHA-256 | 32 | 64 |
| `NOISE_25519_AESGCM_SHA512` | AES-256-GCM | SHA-512 | 64 | 128 |
| `NOISE_25519_AESGCM_BLAKE2S` | AES-256-GCM | BLAKE2s | 32 | 64 |
| `NOISE_25519_AESGCM_BLAKE2B` | AES-256-GCM | BLAKE2b | 64 | 128 |

All suites use X25519 for Diffie-Hellman (DHLEN = 32). Suites with 64-byte hashes (SHA-512, BLAKE2b) automatically truncate HKDF output to 32 bytes for cipher keys per the Noise spec.

| Primitive | Implementation |
|-----------|---------------|
| DH | X25519 via JCA `XDH` / `NamedParameterSpec.X25519` |
| AEAD (ChaCha) | ChaCha20-Poly1305 via `javax.crypto.Cipher` (nonce: 4 zero bytes + 8 LE) |
| AEAD (AES) | AES-256-GCM via `javax.crypto.Cipher("AES/GCM/NoPadding")` (nonce: 4 zero bytes + 8 BE) |
| Hash | SHA-256 via `MessageDigest`, SHA-512 via `MessageDigest("SHA-512")` |
| Hash (BLAKE2) | BLAKE2s (RFC 7693, 32-byte) and BLAKE2b (RFC 7693, 64-byte) via [`blake-hash`](https://github.com/trancee/blake-hash) |
| HMAC/HKDF | `Mac("HmacSHA256")`, `Mac("HmacSHA512")`, or HMAC over BLAKE2 |

Requires **Java 21+**.

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

// Default cipher suite (ChaChaPoly_SHA256)
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

val (msg3, initTransport) = initiator.writeMessage()
val (_, respTransport) = responder.readMessage(msg3)

// Both sides now have authenticated transport + remote static keys
val remoteKey = respTransport!!.remoteStaticKey
```

### XX with AES-GCM + SHA-512

```kotlin
import com.noise.protocol.crypto.CipherSuite

val initiator = HandshakeState(
    pattern = HandshakePattern.XX,
    initiator = true,
    suite = CipherSuite.NOISE_25519_AESGCM_SHA512,
    prologue = ByteArray(0),
    s = NoiseKeyPair.generate()
)

val responder = HandshakeState(
    pattern = HandshakePattern.XX,
    initiator = false,
    suite = CipherSuite.NOISE_25519_AESGCM_SHA512,
    prologue = ByteArray(0),
    s = NoiseKeyPair.generate()
)

// Same message flow as above — suite is transparent after construction
```

### XX with BLAKE2s

```kotlin
val initiator = HandshakeState(
    pattern = HandshakePattern.XX,
    initiator = true,
    suite = CipherSuite.NOISE_25519_CHACHAPOLY_BLAKE2S,
    prologue = ByteArray(0),
    s = NoiseKeyPair.generate()
)
// Both sides must use the same cipher suite
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
    suite: CipherSuite = CipherSuite.NOISE_25519_CHACHAPOLY_SHA256,  // cipher suite
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

### CipherSuite

```kotlin
// Access cipher suites as companion object constants
CipherSuite.NOISE_25519_CHACHAPOLY_SHA256   // default
CipherSuite.NOISE_25519_CHACHAPOLY_SHA512
CipherSuite.NOISE_25519_CHACHAPOLY_BLAKE2S
CipherSuite.NOISE_25519_CHACHAPOLY_BLAKE2B
CipherSuite.NOISE_25519_AESGCM_SHA256
CipherSuite.NOISE_25519_AESGCM_SHA512
CipherSuite.NOISE_25519_AESGCM_BLAKE2S
CipherSuite.NOISE_25519_AESGCM_BLAKE2B

// Properties
suite.dhName      // "25519"
suite.cipherName  // "ChaChaPoly" or "AESGCM"
suite.hashName    // "SHA256", "SHA512", "BLAKE2s", or "BLAKE2b"
suite.dhlen       // 32 (always, for X25519)
suite.hashlen     // 32 (SHA256, BLAKE2s) or 64 (SHA512, BLAKE2b)
suite.blocklen    // 64 (SHA256, BLAKE2s) or 128 (SHA512, BLAKE2b)

// Generate protocol name string
suite.protocolName("XX")  // e.g. "Noise_XX_25519_ChaChaPoly_SHA256"
```

### Error Handling

All errors extend the sealed `NoiseException` class:

| Exception | Description |
|-----------|-------------|
| `DecryptionFailed` | AEAD authentication tag mismatch |
| `HandshakeAlreadyComplete` | Attempted handshake operation after completion |
| `HandshakeNotComplete` | Accessed transport state before handshake finished |
| `NotYourTurn` | Called write on a read turn or vice versa |
| `InvalidMessage` | Handshake message truncated or malformed |
| `InvalidPayloadSize` | Payload exceeds maximum size (65,535 bytes) |
| `InvalidPublicKey` | Public key validation failed |
| `UnknownPattern` | Unknown pattern name in `HandshakePattern.named()` |
| `MissingKey` | Required key not provided |
| `NoKey` | No cipher key set (e.g., rekey before keyed) |
| `NonceExhausted` | Nonce counter overflow (2^64 messages) |

## Testing

```bash
cd android && ./gradlew test
```

73 tests total: 42 parameterized test vector tests (8 cipher suites × 5 base patterns, plus NKpsk0 and IKpsk2 for ChaChaPoly_SHA256) + 1 XXfallback test (validated against cacophony/noise-c canonical vectors from shared `test-vectors/` JSON) + 30 unit tests covering round-trips, error handling, crypto primitives, pattern definitions, and channel binding.

## Architecture

```
lib/src/main/kotlin/com/noise/protocol/
├── NoiseException.kt             # Sealed exception hierarchy
├── crypto/
│   ├── Cipher.kt                # ChaCha20-Poly1305 + AES-256-GCM AEAD
│   ├── CipherSuite.kt           # Cipher suite definitions (8 suites)
│   ├── DH.kt                    # X25519 key pairs + DH via JCA
│   └── Hash.kt                  # SHA-256 + SHA-512, HMAC, HKDF
├── state/
│   ├── CipherState.kt           # AEAD + nonce tracking
│   ├── SymmetricState.kt        # Chaining key + handshake hash
│   └── HandshakeState.kt        # Full handshake state machine
└── pattern/
    └── HandshakePattern.kt      # All pattern definitions
```
