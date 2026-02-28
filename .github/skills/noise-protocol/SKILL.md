---
name: noise-protocol
description: This skill should be used when the user asks to "implement Noise protocol", "create a Noise handshake", "use Noise framework", "build encrypted channel", "implement XX pattern", "implement IK pattern", mentions "Noise_XX", "Noise_IK", "Noise_NK", discusses Diffie-Hellman handshake patterns, or needs guidance on Noise Protocol Framework cryptographic patterns, state machines, message processing, identity hiding, PSK usage, or protocol naming conventions.
---

# Noise Protocol Framework

The Noise Protocol Framework (revision 34, 2018-07-11) constructs crypto protocols using Diffie-Hellman key agreement. It supports mutual/optional authentication, identity hiding, forward secrecy, and zero round-trip encryption.

## Protocol Name Format

`Noise_[Pattern]_[DH]_[Cipher]_[Hash]` (max 255 bytes)

Examples:
- `Noise_XX_25519_AESGCM_SHA256`
- `Noise_IK_448_ChaChaPoly_BLAKE2b`
- `Noise_XXfallback+psk0_25519_ChaChaPoly_SHA256`

## Concrete Algorithms

### DH Functions
| Name | Curve | DHLEN |
|------|-------|-------|
| 25519 | Curve25519 (X25519) | 32 |
| 448 | Curve448 (X448) | 56 |

Both produce all-zero output for invalid public keys.

### Cipher Functions
| Name | Algorithm | Nonce Format |
|------|-----------|-------------|
| ChaChaPoly | ChaCha20-Poly1305 | 32-bit zero + 64-bit LE counter |
| AESGCM | AES-256-GCM, 128-bit tag | 32-bit zero + 64-bit BE counter |

### Hash Functions
| Name | Output | Block Size |
|------|--------|------------|
| SHA256 | 32 bytes | 64 bytes |
| SHA512 | 64 bytes | 128 bytes |
| BLAKE2s | 32 bytes | 64 bytes |
| BLAKE2b | 64 bytes | 128 bytes |

## Handshake State Variables

Each party tracks:
- **s, e** — Local static and ephemeral key pairs
- **rs, re** — Remote static and ephemeral public keys
- **h** — Handshake hash (all sent/received data)
- **ck** — Chaining key (derived from DH outputs)
- **k, n** — Encryption key and counter nonce for payload encryption

## Message Tokens

- **`e`** — Generate ephemeral keypair, send public key in cleartext
- **`s`** — Send static public key (encrypted if k is set)
- **`ee`, `se`, `es`, `ss`** — Perform DH between the named key pairs
- **`psk`** — Mix in a pre-shared symmetric key

## State Machine Objects

### CipherState
Manages encryption with key `k` and nonce `n`:
- `InitializeKey(key)` — Set k, reset n to 0
- `EncryptWithAd(ad, plaintext)` / `DecryptWithAd(ad, ciphertext)` — AEAD encrypt/decrypt, increment n
- `HasKey()` — True if k is set
- `Rekey()` — Derive new k via `ENCRYPT(k, 2^64-1, zeroes, zerolen)`

### SymmetricState
Wraps CipherState with chaining key `ck` and hash `h`:
- `InitializeSymmetric(protocol_name)` — Initialize h and ck from protocol name
- `MixKey(input_key_material)` — HKDF to derive new ck and k
- `MixHash(data)` — h = HASH(h || data)
- `MixKeyAndHash(input_key_material)` — For PSK: derives ck, temp_h, temp_k via HKDF; mixes temp_h into h, sets k = temp_k
- `EncryptAndHash(plaintext)` — Encrypt, then MixHash the ciphertext
- `DecryptAndHash(ciphertext)` — MixHash, then decrypt
- `Split()` — HKDF(ck, empty) to produce two CipherStates for transport

### HandshakeState
Contains SymmetricState plus DH keys and pattern:
- `Initialize(handshake_pattern, initiator, prologue, s, e, rs, re)` — Set up state, MixHash prologue and pre-message keys
- `WriteMessage(payload)` — Process tokens, encrypt payload, return message (+ transport CipherStates if final)
- `ReadMessage(message)` — Process received tokens, decrypt payload

## Handshake Patterns

### One-Way Patterns (no response)

**N** — No sender auth:
```
<- s
...
-> e, es
```

**K** — Sender known to recipient:
```
-> s
<- s
...
-> e, es, ss
```

**X** — Sender transmits static key encrypted:
```
<- s
...
-> e, es, s, ss
```

### Interactive Patterns

**Naming**: First char = initiator's static key handling (N/K/X/I), Second char = responder's (N/K/X).

**NN** (no authentication):
```
-> e
<- e, ee
```

**NK** (responder pre-known):
```
<- s
...
-> e, es
<- e, ee
```

**XX** (mutual certificate exchange):
```
-> e
<- e, ee, s, es
-> s, se
```

**IK** (zero-RTT to known responder):
```
<- s
...
-> e, es, s, ss
<- e, ee, se
```

**KK** (mutual pre-knowledge):
```
-> s
<- s
...
-> e, es, ss
<- e, ee, se
```

For complete pattern listing including NX, KN, KX, XN, XK, IN, IX, and deferred variants, see [references/patterns.md](references/patterns.md).

## Pattern Validity Rules

1. Parties must possess private keys for all DH operations they perform
2. No public key transmitted more than once
3. No DH operation performed more than once
4. Static private key encryption only after ephemeral key contributes (prevents catastrophic key reuse)

## Pre-Shared Keys (PSK)

PSK modifiers append `pskN` to pattern name:
- **psk0** — PSK at start of first message
- **psk1** — PSK at end of first message
- **psk2** — PSK at end of second message

PSK processed via `MixKeyAndHash()`. Parties must not send encrypted data after `psk` unless ephemeral key already sent.

## Compound Protocols (Noise Pipes)

Three-phase protocol:
1. **XX** — Full handshake (first contact)
2. **IK** — Zero-RTT using cached responder key
3. **XXfallback** — Fallback if IK fails (moves Alice's `e` to pre-message)

The `fallback` modifier converts initiator-started pattern to responder-started by moving initiator's first message to pre-message section.

## Security Properties

Payloads have source (authentication) and destination (confidentiality) levels:

**Source**: 0 = none, 1 = sender known (KCI vulnerable), 2 = sender verified (KCI resistant)

**Destination**: 0 = none, 1 = forward-secret, 2 = encrypted to known recipient, 3-5 = varying forward secrecy strengths

For detailed security and identity-hiding properties per pattern, see [references/security-properties.md](references/security-properties.md).

## Implementation Guidance

### Message Size
Messages MUST NOT exceed **65,535 bytes**.

### Nonce Management
- Nonces must never wrap (overflow). Max 2^64 - 1 transport messages per key.
- AESGCM: limit ~72 petabytes per key (birthday bound at 2^56 bytes).

### Key Hygiene
- Static keys: use with single hash algorithm; do not reuse outside Noise
- PSKs: 256-bit entropy minimum; use with single hash algorithm
- Ephemeral keys: generate fresh before each handshake; never reuse

### Application Responsibilities
- Validate remote static keys (certificates, pinning, TOFU)
- Include length fields before Noise messages (recommended: 16-bit big-endian)
- Pad encrypted payloads to hide message sizes
- Use extensible payload formats (JSON, protobuf) for negotiation data
- Implement `GetHandshakeHash()` for channel binding after handshake

### Rekey
Call `Rekey()` periodically to rotate the cipher key without resetting the nonce counter. Uses one-way derivation: `ENCRYPT(k, maxnonce, empty, zeroes)`.

### Out-of-Order Transport (UDP)
Use `SetNonce()` to handle reordering. Application must track received nonces and reject replays.

### Half-Duplex
Strictly alternating parties can use a single CipherState from `Split()` for both directions.
