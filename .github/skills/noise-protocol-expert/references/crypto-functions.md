# Crypto Functions Reference

## Table of Contents
1. [DH functions](#dh-functions)
2. [Cipher functions](#cipher-functions)
3. [Hash functions](#hash-functions)
4. [Derived functions (HMAC, HKDF)](#derived-functions)
5. [Concrete algorithms](#concrete-algorithms)

---

## DH functions

Noise requires three things from DH:

**`GENERATE_KEYPAIR()`**
Generates a new DH key pair (public_key + private_key). The public key is encoded as `DHLEN` bytes.

**`DH(key_pair, public_key)`**
Performs a DH calculation between the private key in `key_pair` and the given `public_key`. Returns `DHLEN` bytes.

Security requirements:
- The Gap-DH problem must be computationally intractable
- Invalid public keys must be handled safely: either return an output that depends only on the public key (not the private key), or signal an error
- `DHLEN` must be ≥ 32 bytes

**`DHLEN`** — size in bytes of public keys and DH outputs.

---

## Cipher functions

**`ENCRYPT(k, n, ad, plaintext)`**
AEAD encryption with:
- `k`: 32-byte cipher key
- `n`: 8-byte unsigned integer nonce (must be unique per key)
- `ad`: associated data
- Returns ciphertext = plaintext + 16 bytes authentication data
- Ciphertext must be indistinguishable from random if key is secret

**`DECRYPT(k, n, ad, ciphertext)`**
AEAD decryption. Returns plaintext or signals authentication failure.

**`REKEY(k)`**
Returns new 32-byte key derived from `k`.
Default: first 32 bytes of `ENCRYPT(k, maxnonce, zerolen, zeros)` where `maxnonce = 2⁶⁴−1`, `zerolen` = zero-length, `zeros` = 32 zero bytes.

---

## Hash functions

**`HASH(data)`**
Collision-resistant hash returning `HASHLEN` bytes.

**`HASHLEN`** — 32 or 64 bytes.

**`BLOCKLEN`** — internal block size for HMAC (`B` in RFC 2104).

---

## Derived functions

**`HMAC-HASH(key, data)`**
Standard HMAC using the `HASH()` function. Only called as part of HKDF.

**`HKDF(chaining_key, input_key_material, num_outputs)`**
- `chaining_key`: `HASHLEN` bytes
- `input_key_material`: 0 bytes, 32 bytes, or `DHLEN` bytes
- Returns 2 or 3 outputs of `HASHLEN` bytes each:

```
temp_key = HMAC-HASH(chaining_key, input_key_material)
output1  = HMAC-HASH(temp_key, byte(0x01))
output2  = HMAC-HASH(temp_key, output1 || byte(0x02))
if num_outputs == 2: return (output1, output2)
output3  = HMAC-HASH(temp_key, output2 || byte(0x03))
return (output1, output2, output3)
```

This is standard HKDF (RFC 5869) with `chaining_key` as the HKDF salt and zero-length HKDF info.

---

## Concrete algorithms

### DH: `25519` (Curve25519 / X25519)

- `GENERATE_KEYPAIR()`: New Curve25519 key pair
- `DH(keypair, public_key)`: X25519 (RFC 7748). Invalid keys produce all-zeros output (alternatively, implementations may signal an error)
- `DHLEN = 32`

**Swift (CryptoKit):**
```swift
import CryptoKit

let privateKey = Curve25519.KeyAgreement.PrivateKey()
let publicKey = privateKey.publicKey

let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(
    with: remotePublicKey
)
// sharedSecret is a SharedSecret — derive bytes with HKDF or use .withUnsafeBytes
```

**Kotlin (BouncyCastle):**
```kotlin
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

val privateKey = X25519PrivateKeyParameters(SecureRandom())
val publicKey = privateKey.generatePublicKey()

val sharedSecret = ByteArray(32)
privateKey.generateSecret(remotePublicKey, sharedSecret, 0)
```

### DH: `448` (Curve448 / X448)

- Same interface as 25519 but with Curve448
- `DHLEN = 56`
- Use with 512-bit hashes (SHA-512 or BLAKE2b)

### Cipher: `ChaChaPoly` (ChaCha20-Poly1305)

- `AEAD_CHACHA20_POLY1305` from RFC 7539
- 96-bit nonce: 32 bits of zeros + little-endian encoding of `n`
- 16-byte authentication tag appended to ciphertext

**Swift (CryptoKit):**
```swift
import CryptoKit

// Build the 12-byte nonce: 4 zero bytes + 8 bytes little-endian n
var nonceBytes = [UInt8](repeating: 0, count: 4)
nonceBytes.append(contentsOf: withUnsafeBytes(of: n.littleEndian) { Array($0) })
let nonce = try ChaChaPoly.Nonce(data: nonceBytes)

let sealedBox = try ChaChaPoly.seal(
    plaintext,
    using: symmetricKey,
    nonce: nonce,
    authenticating: associatedData
)
// sealedBox.ciphertext + sealedBox.tag = the Noise ciphertext
```

**Kotlin (BouncyCastle):**
```kotlin
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.modes.ChaCha20Poly1305

val cipher = ChaCha20Poly1305()
val nonce = ByteArray(12) // 4 zero bytes + 8 bytes little-endian n
ByteBuffer.wrap(nonce, 4, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(n)

cipher.init(true, AEADParameters(KeyParameter(k), 128, nonce, ad))
val output = ByteArray(cipher.getOutputSize(plaintext.size))
var len = cipher.processBytes(plaintext, 0, plaintext.size, output, 0)
len += cipher.doFinal(output, len)
```

### Cipher: `AESGCM` (AES-256-GCM)

- AES256 with GCM, 128-bit tag appended
- 96-bit nonce: 32 bits of zeros + big-endian encoding of `n`
- Harder to implement in constant-time software (prefer ChaChaPoly when no hardware AES)
- Data volume limit: ≤ 2⁵⁶ bytes (≈72 PB) per key

**Swift (CryptoKit):**
```swift
import CryptoKit

var nonceBytes = [UInt8](repeating: 0, count: 4)
nonceBytes.append(contentsOf: withUnsafeBytes(of: n.bigEndian) { Array($0) })
let nonce = try AES.GCM.Nonce(data: nonceBytes)

let sealedBox = try AES.GCM.seal(
    plaintext,
    using: symmetricKey,
    nonce: nonce,
    authenticating: associatedData
)
```

**Kotlin (javax.crypto):**
```kotlin
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

val nonce = ByteArray(12)
ByteBuffer.wrap(nonce, 4, 8).order(ByteOrder.BIG_ENDIAN).putLong(n)

val cipher = Cipher.getInstance("AES/GCM/NoPadding")
cipher.init(
    Cipher.ENCRYPT_MODE,
    SecretKeySpec(k, "AES"),
    GCMParameterSpec(128, nonce)
)
cipher.updateAAD(ad)
val ciphertext = cipher.doFinal(plaintext)
```

### Hash: `SHA256`
- `HASH(input)` = SHA-256
- `HASHLEN = 32`, `BLOCKLEN = 64`

### Hash: `SHA512`
- `HASH(input)` = SHA-512
- `HASHLEN = 64`, `BLOCKLEN = 128`

### Hash: `BLAKE2s`
- `HASH(input)` = BLAKE2s with digest length 32
- `HASHLEN = 32`, `BLOCKLEN = 64`

### Hash: `BLAKE2b`
- `HASH(input)` = BLAKE2b with digest length 64
- `HASHLEN = 64`, `BLOCKLEN = 128`

### Algorithm pairing recommendations

| DH | Hash options | Cipher options | Notes |
|----|-------------|----------------|-------|
| 25519 | SHA256, BLAKE2s, SHA512, BLAKE2b | ChaChaPoly, AESGCM | 256-bit hashes are sufficient; 512-bit adds safety margin |
| 448 | SHA512, BLAKE2b | ChaChaPoly, AESGCM | Must use 512-bit hash with 448 DH |

- **BLAKE2** is faster in software, especially BLAKE2s on 32-bit processors
- **SHA2** has broader library availability
- **ChaChaPoly** is preferred in software; **AESGCM** when hardware AES is available
- Nonce encoding differs: ChaChaPoly = little-endian, AESGCM = big-endian
