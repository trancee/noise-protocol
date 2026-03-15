# Advanced Features Reference

## Table of Contents
1. [Pre-shared symmetric keys (PSK)](#pre-shared-symmetric-keys)
2. [Compound protocols](#compound-protocols)
3. [Noise Pipes](#noise-pipes)
4. [Rekey](#rekey)
5. [Channel binding](#channel-binding)
6. [Out-of-order transport messages](#out-of-order-transport-messages)
7. [Half-duplex protocols](#half-duplex-protocols)
8. [Dummy keys](#dummy-keys)
9. [Handshake indistinguishability](#handshake-indistinguishability)

---

## Pre-shared symmetric keys

PSK mode adds a 32-byte shared secret into the Noise handshake, providing an additional layer of authentication and key material.

### How it works

A `"psk"` token can appear in message patterns. Processing it calls `MixKeyAndHash(psk)`, which:
1. `ck, temp_h, temp_k = HKDF(ck, psk, 3)`
2. `MixHash(temp_h)`
3. If `HASHLEN` is 64: truncate `temp_k` to 32 bytes
4. `InitializeKey(temp_k)`

This mixes the PSK into both encryption keys and the handshake hash.

### Additional rule for ephemeral keys in PSK mode

In non-PSK handshakes, the `"e"` token calls `MixHash(e.public_key)`.
In PSK handshakes, all `"e"` processing is followed by `MixKey(e.public_key)`.

This ensures PSK-based encryption keys are randomized using ephemeral public keys as nonces.

### Validity rule

A party must not send encrypted data after processing a `"psk"` token unless it has previously sent an ephemeral public key (before or after the `"psk"` token). This prevents catastrophic key reuse.

### Pattern modifiers

- `psk0` — places `"psk"` at the beginning of the first handshake message
- `psk1`, `psk2`, ... — places `"psk"` at the end of the 1st, 2nd, ... handshake message

Modifiers can be combined: `XXpsk0+psk3`, `IKpsk1+psk2`, etc.

### Recommended PSK patterns

**One-way:**
```
Npsk0:                    Kpsk0:                    Xpsk1:
  <- s                      -> s                      <- s
  ...                       <- s                      ...
  -> psk, e, es             ...                       -> e, es, s, ss, psk
                            -> psk, e, es, ss
```

Note: `Xpsk1` uses `psk1` (not `psk0`) because the responder likely needs to decrypt the initiator's static key first to determine which PSK to use.

**Interactive (common choices):**

| Base | Recommended PSK variant | Rationale |
|------|------------------------|-----------|
| NN | NNpsk0 or NNpsk2 | Simple symmetric auth |
| NK | NKpsk0 or NKpsk2 | PSK + server auth |
| NX | NXpsk2 | PSK + discovered server auth |
| XN | XNpsk3 | PSK after transmitting initiator key |
| XK | XKpsk3 | PSK after mutual auth |
| XX | XXpsk3 | PSK after mutual auth |
| KN | KNpsk0 or KNpsk2 | PSK + known initiator |
| KK | KKpsk0 or KKpsk2 | PSK + both keys known |
| KX | KXpsk2 | PSK + known initiator, discovered responder |
| IN | INpsk1 or INpsk2 | PSK with immediate initiator key |
| IK | IKpsk1 or IKpsk2 | PSK + immediate initiator, known responder |
| IX | IXpsk2 | PSK with immediate initiator, discovered responder |

### When to use PSK

- **IoT devices** with pre-provisioned shared secrets
- **Additional authentication layer** on top of DH-based auth
- **Environments where DH alone is insufficient** (e.g., post-quantum concerns)
- **WireGuard** uses `IKpsk2` for its handshake

PSK must be a secret value with 256 bits of entropy. Do not use low-entropy passwords.

---

## Compound protocols

### Rationale

Sometimes the responder needs to switch to a different Noise protocol after receiving the initiator's first message:
- Initiator chose unsupported crypto algorithms
- Initiator used a stale version of the responder's static public key
- Protocol negotiation needs

### The `fallback` modifier

Converts an Alice-initiated pattern to a Bob-initiated pattern by turning Alice's first message into a pre-message.

```
XX:                         XXfallback:
  -> e                        -> e
  <- e, ee, s, es             ...
  -> s, se                    <- e, ee, s, es
                              -> s, se
```

The `fallback` modifier can only be applied to patterns where Alice's first message can be interpreted as a pre-message (`"e"`, `"s"`, or `"e, s"`).

### Three-protocol structure

A compound protocol typically uses:
1. **Full protocol** — when no prior information exists (e.g., `XX`)
2. **Zero-RTT protocol** — when initiator has responder's key (e.g., `IK`)
3. **Switch protocol** — when responder can't process the zero-RTT attempt (e.g., `XXfallback`)

Bob distinguishes full vs. zero-RTT by negotiation data (e.g., a type byte before the Noise message).

---

## Noise Pipes

The canonical compound protocol using:

```
XX:   (full handshake)
  -> e
  <- e, ee, s, es
  -> s, se

IK:   (zero-RTT handshake)
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se

XXfallback:   (switch handshake)
  -> e
  ...
  <- e, ee, s, es
  -> s, se
```

### Flow

1. First contact: use `XX` to exchange keys. Alice caches Bob's static public key.
2. Subsequent connections: Alice attempts `IK` for zero-RTT encryption.
3. If Bob can't decrypt (key changed): Bob switches to `XXfallback`.

### Type discrimination

- Bob tries to decrypt the first message as `IK`. If it fails, switch to `XXfallback`.
- Alice distinguishes `IK` response vs. `XXfallback` response using trial decryption.
- For a full handshake, Alice sends an ephemeral key + random padding and uses `XXfallback` for the response (not `XX`, so Bob can use the same trial-decryption logic).

---

## Rekey

`Rekey()` derives a new cipher key from the current one using a one-way function.

### Purpose
- Limit exposure of older ciphertexts if current key is compromised
- Reduce data volume encrypted under a single key (especially relevant for AESGCM)

### Strategies
- **Continuous rekey**: Rekey after every transport message. Simple, best protection, but may be expensive.
- **Periodic rekey**: Rekey after N messages or after a time interval.
- **Signaled rekey**: Application signals rekey to the other party via a message.

### Important notes
- Rekey only updates `k`, not `n`. The nonce continues advancing.
- Even with continuous rekey, a new handshake is needed before 2⁶⁴−1 messages.
- Rekey is application-decided — no pattern modifiers control it.

---

## Channel binding

After the handshake completes, `GetHandshakeHash()` returns the handshake hash `h`, which uniquely identifies the Noise session.

### Use cases
- **Signature-based auth**: Sign `h` to prove participation in this specific session
- **Password-based auth**: Hash `h` with a password for a session-bound auth token
- **Higher-layer binding**: Any application-layer protocol that needs to reference "this session"

### Why use `h` and not `ck`?
- `h` is non-secret (safe to expose)
- `h` is unique per session (not vulnerable to DH tricks with invalid keys that could make `ck` collide)

### Practical examples

**Post-handshake signature authentication**: After XX completes, both sides know each other's static keys but not whether the other party is authorized. To add authorization:

```
// After handshake:
let h = handshakeState.getHandshakeHash()

// Initiator sends a signed token over the transport channel:
let proof = Sign(signingKey, h)   // Ed25519 or similar
send(encrypt(proof))

// Responder verifies:
let proof = decrypt(received)
verify(initiatorSigningPublicKey, h, proof)  // Proves this specific session
```

The signature covers `h`, which binds it to this exact session — replaying the signature into a different session fails because `h` differs.

**Password-based session binding**: Derive a session-bound token from a shared password without exposing the password:

```
let h = handshakeState.getHandshakeHash()
let token = HKDF(salt: h, inputKeyMaterial: password, info: "session-auth", length: 32)
// Both sides compute the same token; exchange and compare
```

**Out-of-band verification (QR code, voice call)**: Display a short fingerprint derived from `h` for the user to verify:

```
let fingerprint = SHA256(h)[0..<8]  // First 8 bytes
display(hex(fingerprint))            // e.g., "a3 f2 91 0c b8 7d e4 12"
```

**Binding to an outer TLS session**: If Noise runs inside TLS, include the TLS session's `tls-exporter` value in the Noise prologue. This binds the Noise session to the TLS session, preventing channel confusion attacks.

---

## Out-of-order transport messages

For UDP or other unreliable transports:

1. Send the nonce `n` alongside each transport message
2. Recipient calls `SetNonce(received_n)` before decrypting
3. Track successfully-decrypted nonce values to reject replays

This introduces denial-of-service and out-of-order handshake concerns that are outside the Noise spec scope.

---

## Half-duplex protocols

For strictly alternating message protocols:
- Use only the first CipherState from `Split()`
- Both parties encrypt/decrypt with the same CipherState
- The second CipherState is discarded

This saves memory and computation but is **catastrophically insecure** if both parties ever encrypt with the same nonce. Only use when the protocol is provably strictly alternating.

---

## Dummy keys

To simulate optional authentication without changing patterns:
- Always execute a pattern like `XX`
- If authentication isn't needed, send a **dummy static public key** (any value)
- This hides whether authentication was requested (same message sizes and timing)

Similarly, **dummy PSKs** (e.g., all zeros) can make PSK support optional within a single pattern.

---

## Handshake indistinguishability

To hide which handshake type is being used (e.g., in Noise Pipes):

1. Pad all handshake payloads to constant size with random bytes
2. Bob tries trial decryption to determine `IK` vs. `XXfallback`
3. Alice uses trial decryption to distinguish `IK` response vs. `XXfallback` response
4. Full handshake Alice sends ephemeral key + random padding, uses `XXfallback`

The ephemeral public keys remain distinguishable from random unless techniques like Elligator are used.
