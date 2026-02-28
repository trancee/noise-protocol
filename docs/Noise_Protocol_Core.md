# Noise Protocol Core Specification

## Scope
This document defines **protocol logic only**. It must not reference any concrete cryptographic algorithm.

---

## 1. Supported Handshakes

- Noise_NN
- Noise_NK
- Noise_KK
- Noise_IK
- Noise_XX

Handshake pattern tables (strictly ordered):
- NN: `-> e`, `<- e, ee`
- NK: `<- s` (pre-message), `-> e, es`, `<- e, ee`
- KK: `-> s`, `<- s` (pre-messages), `-> e, es, ss`, `<- e, ee, se`
- IK: `<- s` (pre-message), `-> e, es, s, ss`, `<- e, ee, se`
- XX: `-> e`, `<- e, ee, s, es`, `-> s, se`

Order is strict and table-driven.

---

## 2. State Machines

### 2.1 CipherState (Logical)

Fields:
- key (opaque byte array or null)
- nonce (uint64, monotonic)

Rules:
- If key == null: plaintext passthrough
- Nonce increments after every encrypt/decrypt
- Rekey = encrypt 32 zero bytes at max nonce

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

---

## 5. Test Requirements

- Must pass official Noise_XX vectors
- Cross-platform transcript equality
- Deterministic behavior with forced keys
