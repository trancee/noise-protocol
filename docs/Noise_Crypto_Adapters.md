# Noise Cryptographic Adapter Specification

## Scope
This document defines **cryptographic interfaces only**.
No protocol logic is allowed here.

---

## Android implementation status (`android/noise-crypto`)

Current adapter set:
- DH: `X25519DiffieHellmanAdapter` (`NoiseDhAlgorithm.X25519`), `X448DiffieHellmanAdapter` (`NoiseDhAlgorithm.X448`)
- AEAD: `ChaCha20Poly1305CipherAdapter`, `AesGcmCipherAdapter`
- Hash/HKDF:
  - `Sha256HashAdapter` + `HkdfSha256Adapter`
  - `Sha512HashAdapter` + `HkdfSha512Adapter`
  - `Blake2sHashAdapter` + `HkdfBlake2sAdapter`
  - `Blake2bHashAdapter` + `HkdfBlake2bAdapter`
- Provider wiring: `CryptoProvider#createSuite(...)` returns a `NoiseCryptoSuite` for `noise-core`

Adapter contract alignment:
- ChaCha20-Poly1305 nonce format: 32-bit zero prefix + 64-bit little-endian counter
- AES-GCM nonce format: 32-bit zero prefix + 64-bit big-endian counter
- Rekey behavior: `ENCRYPT(k, 2^64-1, empty, zeroes(32))`, truncated to 32-byte key material

---

## 1. Diffie-Hellman (DH) Interface

Functions:
- keygen() -> (private, public)
- dh(private, public) -> shared_secret

Properties:
- Constant-time
- Zeroize private material
- Fixed key sizes

Examples:
- X25519
- X448

---

## 2. AEAD Interface

Functions:
- encrypt(key, nonce, ad, plaintext) -> ciphertext
- decrypt(key, nonce, ad, ciphertext) -> plaintext | error
- rekey(key) -> new_key

Properties:
- Nonce = 64-bit LE counter
- No nonce reuse
- Authentication failure is fatal

Examples:
- ChaCha20-Poly1305
- AES-GCM

---

## 3. Hash / HKDF Interface

Functions:
- hash(data) -> digest
- hmac(key, data) -> mac
- hkdf(chaining_key, ikm, outputs=2) -> (ck, temp_k)

Properties:
- Deterministic
- Output sizes fixed per algorithm

Examples:
- BLAKE2s
- BLAKE2b
- SHA-256
- SHA-512

---

## 3.1 iOS Built-in Adapter Names

`ios/Sources/NoiseCryptoAdapters` provides built-in adapters and registry/factory wiring by algorithm name:

- DH: `25519` -> `Curve25519DiffieHellmanAdapter`
- DH: `448` -> `X448DiffieHellmanAdapter`
- AEAD: `ChaChaPoly` -> `ChaChaPolyCipherAdapter`
- AEAD: `AESGCM` -> `AESGCMCipherAdapter`
- Hash/HKDF: `SHA256` -> `SHA256HashAdapter`
- Hash/HKDF: `SHA512` -> `SHA512HashAdapter`
- Hash/HKDF: `BLAKE2s` -> `Blake2sHashAdapter`
- Hash/HKDF: `BLAKE2b` -> `Blake2bHashAdapter`

Use `NoiseCryptoAdapterRegistry(registeringBuiltIns: true)` and `NoiseCryptoAdapterFactory` to construct a `NoiseCryptoProvider` from `NoiseCryptoSuiteDescriptor` without adding protocol logic to adapters.

Current status:
- Built-in iOS DH support now includes both `25519` and `448`.
- Native iOS X448 support is implemented with a pure-Swift bigint dependency (`attaswift/BigInt` pinned exactly at `5.7.0` in both SwiftPM entrypoints) because `apple/swift-numerics` does not currently ship arbitrary-precision integers.
- `Curve25519DiffieHellmanAdapter` and `X448DiffieHellmanAdapter` both expose deterministic private-key derivation helpers so the official-vector converter can derive local public keys from official private-key inputs before replaying the transcript through `NoiseVectorRunner`.
- Native iOS hash support now includes `SHA256`, `SHA512`, `BLAKE2s`, and `BLAKE2b`, implemented in-repo so the built-in registry can execute the full shared fixture corpus without adding another external dependency.
- Representative official `448` vector conversion now succeeds on iOS, and the repository parity script compares Android and iOS outputs for that path as well.
- The native iOS X448 rollout is recorded in `plan/feature-ios-x448-support-1.md` as the implementation and parity history for that work.

---

## 4. Security Requirements

- Zeroize secrets after use
- No logging of key material
- Fail closed on any error
- Constant-time DH only

---

## 5. Swap Rules

- Adapters may be swapped independently
- Protocol code must remain unchanged
- All test vectors must still pass
