# Copilot Instructions

## Project overview

This is a Noise Protocol Framework implementation targeting mobile: **Swift** (iOS/macOS with CryptoKit) and **Kotlin** (Android with native platform APIs). The goal is a spec-conformant (revision 34) implementation built from primitives, not wrapping an existing Noise library. Uses platform-native crypto libraries plus [`blake-hash`](https://github.com/trancee/blake-hash) for BLAKE2 hashing.

## Architecture

The implementation follows a layered design, identical in both platforms:

1. **Crypto primitives** — thin wrappers around platform APIs (CryptoKit on Apple, BouncyCastle on Android). Default cipher suite: `Noise_XX_25519_ChaChaPoly_SHA256`.
2. **State machine** — three nested objects: `CipherState` → `SymmetricState` → `HandshakeState`. These operate on raw bytes and are transport-agnostic.
3. **Transport integration** — framing (16-bit big-endian length prefix for TCP), BLE fragmentation, WebSocket binary frames.
4. **Key storage** — Keychain Services on iOS, Android Keystore (AES-GCM wrapped) on Android.

After the handshake completes, `Split()` returns two `CipherState` objects: `c1` (initiator→responder) and `c2` (responder→initiator).

## Crypto conventions

- **Nonce encoding**: 4 zero bytes + 8 bytes little-endian for ChaChaPoly.
- **HASHLEN truncation**: When using SHA-512/BLAKE2b (`HASHLEN` = 64), `MixKey()` and `Split()` must truncate HKDF output to 32 bytes. SHA-256 (`HASHLEN` = 32) needs no truncation.
- **DH token roles**: `"es"` means initiator computes `DH(e, rs)`, responder computes `DH(s, re)`. The first letter refers to the initiator's key type, the second to the responder's.
- **Nonce on decryption failure**: Do NOT increment. The spec requires `n` stays unchanged on failed `DecryptWithAd`.
- **Rekey**: `ENCRYPT(k, maxnonce, empty, zeros_32)`, take first 32 bytes.
- **Max message size**: 65,535 bytes.

## Platform-specific notes

### Swift
- Use `Curve25519.KeyAgreement` for DH, `ChaChaPoly` for AEAD, `SHA256`/`HMAC<SHA256>` for hashing — all from CryptoKit.
- Use `Data` for byte sequences, `SymmetricKey` for cipher keys.
- Store static keys via Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
- Target Swift 6+ / Xcode 16+ if using Swift Testing (`@Test`, `#expect`).

### Kotlin
- Uses `java.security`, `javax.crypto`, Android platform APIs, and [`blake-hash`](https://github.com/trancee/blake-hash) (`ch.trancee:blake-hash:1.1.0`) for BLAKE2 hashing.
- `javax.crypto.Cipher("ChaCha20-Poly1305")` for AEAD (API 28+, which is the minimum for this project).
- `java.security.KeyPairGenerator("XDH")` with `NamedParameterSpec("X25519")` for DH key generation (API 33+ / Java 11+). Use `KeyAgreement("XDH")` for the shared secret computation.
- `javax.crypto.Mac("HmacSHA256")` and `java.security.MessageDigest("SHA-256")` for hashing.
- Wrap private key bytes with a Keystore-backed AES-GCM key for storage.
- For Kotlin Multiplatform, use `expect`/`actual` for crypto primitives.

## Testing conventions

- **Key generation must be injectable** — accept a `KeyPairGenerator` interface/protocol so tests can supply deterministic keys from test vectors.
- **Test each layer independently**: CipherState, SymmetricState, HandshakeState, then full round-trips.
- **Validate against spec test vectors**: use the curated vectors in `.claude/skills/noise-protocol-expert/references/test-vectors.md` to verify byte-for-byte correctness. Override the RNG/key generator to return the vector's ephemeral key, then compare every intermediate value (handshake hash, ciphertext, transport messages) against expected output. A passing test vector means the implementation is spec-conformant.
- **Cross-platform validation**: both Swift and Kotlin must pass the same test vectors with identical outputs.
- **Error cases to cover**: invalid public keys, authentication failure, nonce exhaustion, truncated messages.

## Key reference material

Detailed spec guidance, test vectors, and platform patterns live in `.claude/skills/noise-protocol-expert/references/`:
- `processing-rules.md` — full state machine pseudocode
- `handshake-patterns.md` — pattern selection and security properties
- `crypto-functions.md` — algorithm details (key sizes, nonce encoding)
- `test-vectors.md` — known-good inputs/outputs for implementation validation
- `mobile-implementations.md` — platform-specific code patterns
- `advanced-features.md` — PSK, Noise Pipes, rekey, channel binding
