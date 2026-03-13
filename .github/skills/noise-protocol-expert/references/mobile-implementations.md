# Mobile Implementation Reference (Swift & Kotlin)

## Table of Contents
1. [Architecture overview](#architecture-overview)
2. [Swift implementation](#swift-implementation)
3. [Kotlin implementation](#kotlin-implementation)
4. [Key management](#key-management)
5. [Transport integration](#transport-integration)
6. [Testing strategies](#testing-strategies)

---

## Architecture overview

A Noise implementation on mobile has these layers:

```
┌─────────────────────────────┐
│  Application Protocol       │  Payloads, framing, negotiation
├─────────────────────────────┤
│  Noise State Machine        │  HandshakeState → CipherState
├─────────────────────────────┤
│  Crypto Primitives          │  X25519, ChaCha20-Poly1305, SHA-256
├─────────────────────────────┤
│  Transport                  │  TCP, WebSocket, Bluetooth, UDP
├─────────────────────────────┤
│  Key Storage                │  Keychain (iOS), Keystore (Android)
└─────────────────────────────┘
```

Build from the bottom up. The crypto primitives should be thin wrappers around platform APIs. The state machine operates on byte arrays and is transport-agnostic.

---

## Swift implementation

### Crypto primitives with CryptoKit

CryptoKit (available since iOS 13) provides everything needed for a `Noise_XX_25519_ChaChaPoly_SHA256` implementation:

```swift
import CryptoKit
import Foundation

// --- DH Functions ---

struct NoiseKeyPair {
    let privateKey: Curve25519.KeyAgreement.PrivateKey
    var publicKey: Data {
        Data(privateKey.publicKey.rawRepresentation)
    }
    
    init() {
        self.privateKey = .init()
    }
    
    init(privateKey: Curve25519.KeyAgreement.PrivateKey) {
        self.privateKey = privateKey
    }
    
    func dh(remotePublicKey: Data) throws -> Data {
        let remotePub = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: remotePublicKey
        )
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: remotePub)
        // Extract raw bytes from SharedSecret
        return shared.withUnsafeBytes { Data($0) }
    }
}

let dhlen = 32

// --- Cipher Functions ---

struct NoiseCipher {
    static func encrypt(k: SymmetricKey, n: UInt64, ad: Data, plaintext: Data) throws -> Data {
        let nonce = try makeNonce(n)
        let sealedBox = try ChaChaPoly.seal(
            plaintext,
            using: k,
            nonce: nonce,
            authenticating: ad
        )
        return sealedBox.ciphertext + sealedBox.tag
    }
    
    static func decrypt(k: SymmetricKey, n: UInt64, ad: Data, ciphertext: Data) throws -> Data {
        let nonce = try makeNonce(n)
        let tagStart = ciphertext.count - 16
        let ct = ciphertext.prefix(tagStart)
        let tag = ciphertext.suffix(16)
        let sealedBox = try ChaChaPoly.SealedBox(
            nonce: nonce,
            ciphertext: ct,
            tag: tag
        )
        return try ChaChaPoly.open(sealedBox, using: k, authenticating: ad)
    }
    
    // ChaChaPoly nonce: 4 zero bytes + 8 bytes little-endian n
    private static func makeNonce(_ n: UInt64) throws -> ChaChaPoly.Nonce {
        var bytes = [UInt8](repeating: 0, count: 4)
        withUnsafeBytes(of: n.littleEndian) { bytes.append(contentsOf: $0) }
        return try ChaChaPoly.Nonce(data: bytes)
    }
}

// --- Hash Functions ---

struct NoiseHash {
    static let hashlen = 32
    static let blocklen = 64
    
    static func hash(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
    
    static func hmacHash(key: Data, data: Data) -> Data {
        let hmac = HMAC<SHA256>.authenticationCode(
            for: data,
            using: SymmetricKey(data: key)
        )
        return Data(hmac)
    }
    
    static func hkdf(
        chainingKey: Data,
        inputKeyMaterial: Data,
        numOutputs: Int
    ) -> [Data] {
        let tempKey = hmacHash(key: chainingKey, data: inputKeyMaterial)
        let output1 = hmacHash(key: tempKey, data: Data([0x01]))
        let output2 = hmacHash(key: tempKey, data: output1 + Data([0x02]))
        if numOutputs == 2 { return [output1, output2] }
        let output3 = hmacHash(key: tempKey, data: output2 + Data([0x03]))
        return [output1, output2, output3]
    }
}
```

### CipherState in Swift

```swift
class CipherState {
    private var k: SymmetricKey?
    private var n: UInt64 = 0
    
    func initializeKey(_ key: Data?) {
        k = key.map { SymmetricKey(data: $0) }
        n = 0
    }
    
    var hasKey: Bool { k != nil }
    
    func encryptWithAd(_ ad: Data, plaintext: Data) throws -> Data {
        guard let key = k else { return plaintext }
        let ct = try NoiseCipher.encrypt(k: key, n: n, ad: ad, plaintext: plaintext)
        n += 1
        guard n < UInt64.max else { throw NoiseError.nonceExhausted }
        return ct
    }
    
    func decryptWithAd(_ ad: Data, ciphertext: Data) throws -> Data {
        guard let key = k else { return ciphertext }
        let pt = try NoiseCipher.decrypt(k: key, n: n, ad: ad, ciphertext: ciphertext)
        n += 1
        return pt
    }
    
    func rekey() throws {
        guard let key = k else { throw NoiseError.noKey }
        let zeros = Data(repeating: 0, count: 32)
        let newKeyData = try NoiseCipher.encrypt(
            k: key, n: UInt64.max, ad: Data(), plaintext: zeros
        ).prefix(32)
        k = SymmetricKey(data: newKeyData)
    }
}

enum NoiseError: Error {
    case nonceExhausted
    case noKey
    case decryptionFailed
    case invalidPublicKey
    case handshakeFailed
}
```

### SymmetricState and HandshakeState

Follow the same structure as the processing rules reference. The key implementation detail for Swift:

- Use `Data` for all byte sequences
- `SymmetricKey` from CryptoKit for cipher keys
- When `HASHLEN` is 32 (SHA-256), no truncation is needed in `MixKey` or `Split`
- For SHA-512 (`HASHLEN` = 64), truncate with `.prefix(32)`

---

## Kotlin implementation

### Crypto primitives

For Android, use BouncyCastle (widely available) or Tink. For Kotlin Multiplatform, wrap platform-specific crypto behind `expect`/`actual`.

```kotlin
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// --- DH Functions ---

class NoiseKeyPair(
    val privateKey: X25519PrivateKeyParameters =
        X25519PrivateKeyParameters(SecureRandom())
) {
    val publicKey: ByteArray
        get() = privateKey.generatePublicKey().encoded

    fun dh(remotePublicKey: ByteArray): ByteArray {
        val remotePub = X25519PublicKeyParameters(remotePublicKey, 0)
        val agreement = X25519Agreement()
        agreement.init(privateKey)
        val shared = ByteArray(32)
        agreement.calculateAgreement(remotePub, shared, 0)
        return shared
    }
}

const val DHLEN = 32

// --- Cipher Functions (ChaChaPoly) ---

object NoiseCipher {
    fun encrypt(k: ByteArray, n: Long, ad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305")
        val nonce = makeNonce(n)
        val spec = GCMParameterSpec(128, nonce)  // Poly1305 tag treated as 128-bit
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, SecretKeySpec(k, "ChaCha20"), spec)
        cipher.updateAAD(ad)
        return cipher.doFinal(plaintext)
    }

    fun decrypt(k: ByteArray, n: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = javax.crypto.Cipher.getInstance("ChaCha20-Poly1305")
        val nonce = makeNonce(n)
        val spec = GCMParameterSpec(128, nonce)
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, SecretKeySpec(k, "ChaCha20"), spec)
        cipher.updateAAD(ad)
        return cipher.doFinal(ciphertext)
    }

    // ChaChaPoly nonce: 4 zero bytes + 8 bytes little-endian n
    private fun makeNonce(n: Long): ByteArray {
        val nonce = ByteArray(12)
        ByteBuffer.wrap(nonce, 4, 8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putLong(n)
        return nonce
    }
}

// --- Hash Functions (SHA-256) ---

object NoiseHash {
    const val HASHLEN = 32
    const val BLOCKLEN = 64

    fun hash(data: ByteArray): ByteArray {
        return java.security.MessageDigest.getInstance("SHA-256").digest(data)
    }

    fun hmacHash(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun hkdf(
        chainingKey: ByteArray,
        inputKeyMaterial: ByteArray,
        numOutputs: Int
    ): List<ByteArray> {
        val tempKey = hmacHash(chainingKey, inputKeyMaterial)
        val output1 = hmacHash(tempKey, byteArrayOf(0x01))
        val output2 = hmacHash(tempKey, output1 + byteArrayOf(0x02))
        if (numOutputs == 2) return listOf(output1, output2)
        val output3 = hmacHash(tempKey, output2 + byteArrayOf(0x03))
        return listOf(output1, output2, output3)
    }
}
```

### CipherState in Kotlin

```kotlin
class CipherState {
    private var k: ByteArray? = null
    private var n: Long = 0

    fun initializeKey(key: ByteArray?) {
        k = key
        n = 0
    }

    val hasKey: Boolean get() = k != null

    fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
        val key = k ?: return plaintext
        val ct = NoiseCipher.encrypt(key, n, ad, plaintext)
        n++
        check(n < Long.MAX_VALUE) { "Nonce exhausted" }
        return ct
    }

    fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val key = k ?: return ciphertext
        val pt = NoiseCipher.decrypt(key, n, ad, ciphertext)
        n++
        return pt
    }

    fun rekey() {
        val key = k ?: error("No key set")
        val zeros = ByteArray(32)
        val newKey = NoiseCipher.encrypt(key, Long.MAX_VALUE, ByteArray(0), zeros)
        k = newKey.copyOfRange(0, 32)
    }
}
```

### Android-specific: ChaCha20-Poly1305 availability

`ChaCha20-Poly1305` in `javax.crypto.Cipher` requires API level 28+ (Android 9). For older API levels:
- Use BouncyCastle's `ChaCha20Poly1305` engine directly
- Or use Tink's `AeadFactory` with ChaCha20Poly1305

---

## Key management

### iOS: Keychain Services

Store static key pairs in the Keychain for persistence and security:

```swift
import Security

func saveStaticKey(_ privateKeyData: Data, tag: String) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecValueData as String: privateKeyData,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    ]
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw NoiseError.keyStoreFailed
    }
}
```

For Curve25519 keys specifically, store the 32-byte raw private key and reconstruct on load:
```swift
let restored = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: storedData)
```

### Android: Android Keystore

The Android Keystore doesn't directly support X25519. Store the raw private key bytes encrypted with an AES key that lives in the Keystore:

```kotlin
// Generate a Keystore-backed AES key for wrapping
val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
)
keyGenerator.init(
    KeyGenParameterSpec.Builder("noise_key_wrapper",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .build()
)
val wrapperKey = keyGenerator.generateKey()

// Encrypt the Noise static private key with the wrapper
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(Cipher.ENCRYPT_MODE, wrapperKey)
val encryptedKey = cipher.doFinal(noisePrivateKeyBytes)
val iv = cipher.iv
// Store encryptedKey + iv in SharedPreferences or a file
```

---

## Transport integration

### TCP (most common)

Frame each Noise message with a 16-bit big-endian length prefix:

```swift
// Swift: Send
func sendNoiseMessage(_ message: Data, over stream: OutputStream) {
    var length = UInt16(message.count).bigEndian
    let lengthBytes = withUnsafeBytes(of: &length) { Data($0) }
    stream.write([UInt8](lengthBytes), maxLength: 2)
    stream.write([UInt8](message), maxLength: message.count)
}

// Swift: Receive
func receiveNoiseMessage(from stream: InputStream) -> Data {
    var lengthBytes = [UInt8](repeating: 0, count: 2)
    stream.read(&lengthBytes, maxLength: 2)
    let length = Int(UInt16(bigEndian: Data(lengthBytes).withUnsafeBytes { $0.load(as: UInt16.self) }))
    var message = [UInt8](repeating: 0, count: length)
    stream.read(&message, maxLength: length)
    return Data(message)
}
```

### Bluetooth Low Energy

BLE has natural message boundaries (characteristic writes/notifications), so length framing may not be needed. Key considerations:
- MTU limits message size (typically 20 bytes default, up to 512 negotiated)
- For messages larger than MTU, implement fragmentation at the application layer
- Use notify/indicate for responder→initiator messages
- Use write-with-response for handshake messages (reliability)
- Use write-without-response for transport messages if latency matters

### WebSocket

WebSocket frames already provide message boundaries. Send each Noise message as a binary frame.

---

## Testing strategies

### Unit testing the state machine

Test vectors are essential. Use known test vectors from the Noise spec implementers:
- [noise-c test vectors](https://github.com/rweather/noise-c)
- [cacophony test vectors](https://github.com/centromere/cacophony) (Haskell)

Each test vector specifies:
- Handshake pattern and crypto algorithms
- Pre-shared keys (initiator static, responder static, PSKs)
- Ephemeral keys (for deterministic testing, inject rather than generate)
- Expected handshake messages (byte-for-byte)
- Expected handshake hash
- Expected transport messages

### Testing approach

1. **Make key generation injectable** — accept a key pair factory so tests can inject deterministic keys
2. **Test each state object independently** — CipherState, SymmetricState, HandshakeState
3. **Test full handshake round-trips** — initiator and responder process all messages
4. **Test error cases** — invalid keys, authentication failure, nonce exhaustion, truncated messages
5. **Cross-platform testing** — if building for both iOS and Android, run the same test vectors on both

```swift
// Swift: Injectable key generation for testing
protocol KeyPairGenerator {
    func generate() -> NoiseKeyPair
}

struct RandomKeyPairGenerator: KeyPairGenerator {
    func generate() -> NoiseKeyPair { NoiseKeyPair() }
}

struct DeterministicKeyPairGenerator: KeyPairGenerator {
    let privateKeyData: Data
    func generate() -> NoiseKeyPair {
        let pk = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        return NoiseKeyPair(privateKey: pk)
    }
}
```

```kotlin
// Kotlin: Injectable key generation for testing
interface KeyPairGenerator {
    fun generate(): NoiseKeyPair
}

class RandomKeyPairGenerator : KeyPairGenerator {
    override fun generate() = NoiseKeyPair()
}

class DeterministicKeyPairGenerator(
    private val privateKeyData: ByteArray
) : KeyPairGenerator {
    override fun generate() = NoiseKeyPair(
        X25519PrivateKeyParameters(privateKeyData, 0)
    )
}
```
