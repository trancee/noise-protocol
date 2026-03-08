# Noise Protocol Core Specification

## Scope
This document defines **protocol logic only**. It must not reference any concrete cryptographic algorithm.

---

## 1. Supported Handshakes

- Noise_NN
- Noise_NK
- Noise_NX
- Noise_XN
- Noise_XK
- Noise_KN
- Noise_KK
- Noise_KX
- Noise_IN
- Noise_IK
- Noise_IX
- Noise_XX

Handshake pattern tables (strictly ordered):
- NN: `-> e`, `<- e, ee`
- NK: `<- s` (pre-message), `-> e, es`, `<- e, ee`
- NX: `-> e`, `<- e, ee, s, es`
- XN: `-> e`, `<- e, ee`, `-> s, se`
- XK: `<- s` (pre-message), `-> e, es`, `<- e, ee`, `-> s, se`
- KN: `-> s` (pre-message), `-> e`, `<- e, ee, se`
- KK: `-> s`, `<- s` (pre-messages), `-> e, es, ss`, `<- e, ee, se`
- KX: `-> s` (pre-message), `-> e`, `<- e, ee, se, s, es`
- IN: `-> e, s`, `<- e, ee, se`
- IK: `<- s` (pre-message), `-> e, es, s, ss`, `<- e, ee, se`
- IX: `-> e, s`, `<- e, ee, se, s, es`
- XX: `-> e`, `<- e, ee, s, es`, `-> s, se`

Order is strict and table-driven.

Shared vector note:
- The shared repository vector corpus currently remains scoped to `NN`, `NK`, `KK`, `IK`, and `XX`.

---

## 2. State Machines

### 2.1 CipherState (Logical)

Fields:
- key (opaque byte array or null)
- nonce (uint64, monotonic)

Rules:
- If key == null: plaintext passthrough
- Nonce increments after every encrypt/decrypt
- Failed decrypt authentication must not advance the nonce
- Rekey = encrypt 32 zero bytes at max nonce
- Implementations may expose monotonic nonce override helpers for out-of-order transport, but must reject nonce regression.

---

### 2.2 SymmetricState

Fields:
- chaining_key
- handshake_hash
- cipher_state

Initialization:
- handshake_hash = HASH(protocol_name)
- chaining_key = handshake_hash

Operations:
- mix_hash(data)
- mix_key(ikm)
- encrypt_and_hash(plaintext)
- decrypt_and_hash(ciphertext)
- split() -> (tx, rx)

---

### 2.3 HandshakeState

Fields:
- s, e (local keys)
- rs, re (remote keys)
- symmetric_state
- message_patterns

Rules:
- Driven entirely by handshake pattern table
- No branching on initiator/responder except message direction
- Payload encrypted after all pattern tokens
- Errors abort handshake immediately
- The current handshake hash should be available to callers for channel binding during or after the handshake.
- Public APIs should expose enough progress state for callers to enforce turn-taking cleanly, including whether the handshake is complete and which side is expected to send next.

Repository API note:
- Both platform surfaces expose stateful handshake-session style APIs on top of the underlying handshake state machine, with framed message helpers and progress inspection for strict turn-taking.

---

## 3. Transport Phase

- Uses CipherStates from split()
- Separate TX and RX
- Rekey allowed at any time
- No handshake logic allowed

---

## 4. Serialization Rules

- Raw byte concatenation
- No implicit length prefixes
- Public keys sent verbatim
- Ciphertext includes AEAD tag inline
- No endianness assumptions
- When host applications want framed message helpers, the Android and iOS core APIs expose a 16-bit big-endian `HandshakeMessage`/`NoiseHandshakeMessage` encoding that rejects frames above 65,535 bytes.

---

## 5. Test Requirements

- Must pass official Noise_XX vectors
- Cross-platform transcript equality
- Deterministic behavior with forced keys
