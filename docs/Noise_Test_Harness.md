# Noise Test Harness Specification

## Scope
This document defines the **test harness requirements** for validating a Noise protocol implementation.
It applies to **all protocol cores and crypto adapter combinations**.

The test harness is **mandatory** and normative.

---

## 1. Goals

The test harness MUST ensure:

- Bit-for-bit compatibility with the Noise specification
- Cross-platform interoperability
- Deterministic behavior under forced inputs
- Correct failure behavior
- Safe swapping of cryptographic adapters

---

## 2. Test Vector Categories

### 2.1 Golden Test Vectors

Golden vectors are authoritative and MUST pass.

Each vector includes:
- Protocol name (e.g. Noise_XX_25519_ChaChaPoly_BLAKE2s)
- Initiator static key pair
- Responder static key pair
- Forced ephemeral key pairs
- Prologue (optional)
- Payloads per message
- Expected ciphertext outputs
- Final handshake hash
- Transport TX/RX keys

Golden vectors MUST be shared across all implementations.

---

### 2.2 Deterministic Handshake Tests

Purpose:
- Ensure protocol logic correctness independent of RNG

Rules:
- Ephemeral keys are injected, not generated
- Payloads are fixed
- Outputs must match exactly

Failure of any deterministic test is fatal.

---

### 2.3 Cross-Implementation Interop Tests

Purpose:
- Validate interoperability across platforms/languages

Procedure:
1. Run handshake on Implementation A
2. Run same handshake on Implementation B
3. Compare:
   - All handshake messages
   - Transcript hash
   - Split transport keys

All bytes MUST match exactly.

---

## 3. Negative Test Cases

### 3.1 Authentication Failures
- Corrupted ciphertext
- Corrupted authentication tag
- Modified associated data

Expected result:
- Decryption failure
- Immediate abort
- No state reuse

---

### 3.2 Nonce Misuse
- Nonce reuse
- Nonce overflow

Expected result:
- Fatal error
- Transport phase halted

---

### 3.3 Message Ordering
- Reordered handshake messages
- Duplicate messages

Expected result:
- Handshake abort

---

### 3.4 DH Failures
- Invalid public keys
- Incorrect key sizes

Expected result:
- Handshake abort
- No partial state retained

---

## 4. Transport Phase Tests

### 4.1 Encrypt / Decrypt Symmetry
- TX encrypt → RX decrypt
- Payload recovered exactly

### 4.2 Rekey Tests
- Rekey at deterministic intervals
- Verify new keys differ
- Verify old keys no longer decrypt

---

## 5. Adapter Swap Tests

Purpose:
- Ensure cryptographic pluggability

Procedure:
1. Run full test suite with Adapter Set A
2. Swap exactly one adapter (e.g. AEAD)
3. Re-run all tests

Rules:
- Protocol code must not change
- All tests must still pass

---

## 6. Memory & Safety Tests

- Ensure secrets are zeroized after use
- Ensure no key material is logged or exposed
- Ensure failure paths clean state

---

## 7. Performance Regression Tests

(Not correctness-fatal, but mandatory to measure)

- Handshake allocations count
- Transport allocations count (must be zero)
- Encryption/decryption throughput
- Rekey cost

---

## 8. Test Harness Interface (Conceptual)

The harness MUST expose:

- Load test vectors
- Inject static and ephemeral keys
- Execute handshake step-by-step
- Capture intermediate state
- Compare outputs byte-for-byte

No platform-specific behavior is allowed in test logic.

---

## 9. Acceptance Criteria

An implementation is accepted if and only if:

- All golden vectors pass
- All negative tests fail correctly
- Cross-platform transcripts are identical
- Adapter swap tests pass
- No protocol logic changes were required

---

## 10. Non-Goals

The test harness does NOT attempt to:

- Prove cryptographic security
- Detect microarchitectural side channels
- Replace formal verification

---

## 11. Versioning

- Test vectors MUST be versioned
- Noise spec revision MUST be recorded
- Any change invalidates previous approvals

---

## 12. Shared Vector Contract and Layout

- Canonical schema: `test-vectors/schema/noise-vector-v1.schema.json`
- Fixtures must declare `schema_version` and follow the matching major folder: `test-vectors/fixtures/v1/`
- If the contract changes incompatibly, add a new schema file (`...-v2.schema.json`) and write fixtures under `fixtures/v2/`
- Each fixture must include protocol metadata, input key material/prologue/payloads, expected handshake outputs (messages/hash/split keys), and negative-case metadata
