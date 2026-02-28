# Noise Cryptographic Adapter Specification

## Scope
This document defines **cryptographic interfaces only**.
No protocol logic is allowed here.

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
- SHA-256
- SHA-512

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
