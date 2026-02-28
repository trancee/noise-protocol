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
- Protocol name (e.g. Noise_XX_25519_AESGCM_SHA256)
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
- Android benchmark-oriented tests include:
  - `NoiseCoreBenchmarkTest` (tagged `benchmark`) for deterministic handshake throughput across
    `NN`, `NK`, `KK`, `IK`, and `XX`, plus transport encrypt/decrypt loops.
  - `CryptoProviderBenchmarkTest` (tagged `benchmark`) for provider crypto-variation coverage:
    (`X25519` | `X448`) + (`ChaCha20-Poly1305` | `AES-GCM`) +
    (`SHA-256` | `SHA-512` | `BLAKE2s` | `BLAKE2b`).
  - Metrics are printed as `elapsed_ns`, `ns_per_op`, and `ops_per_s` without timing thresholds.

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
- Current v1 corpus covers the full matrix (`80` fixtures):
  - patterns: `NN`, `NK`, `KK`, `IK`, `XX`
  - DH: `25519`, `448`
  - ciphers: `ChaChaPoly`, `AESGCM`
  - hashes: `SHA256`, `SHA512`, `BLAKE2s`, `BLAKE2b`
- Fixture file naming for generated matrix vectors is:
  `noise-<pattern-lower>-<dh>-<cipher-lower>-<hash-lower>.json`

---

## 13. Android Harness Usage

- Android module: `android/noise-testing`
- `NoiseVectorFixtureLoader` loads v1 fixtures directly from `test-vectors/fixtures/v1/`
- `NoiseTestHarness.runDeterministic(...)` coordinates deterministic `HandshakeState` execution with injected fixture key material
- `NoiseTestHarness.runNegativeCase(...)` applies fixture-driven mutation hooks (including tag tamper and handshake message-order mutations) and reports failures as harness results
- `cd android && gradle --no-daemon :noise-core:test :noise-crypto:test --tests '*Benchmark*'`
  runs benchmark-oriented Android coverage (core handshake/transport and provider crypto variations)
  with correctness assertions

---

## 14. iOS Harness Integration

- `NoiseVectorFixtureLoader` loads shared fixtures from `test-vectors/fixtures/v1/` and decodes the v1 contract.
- `NoiseVectorRunner.run(_:)` executes deterministic handshake orchestration using `NoiseCore` and crypto adapters selected from the fixture suite metadata.
- `NoiseVectorRunner.verifyExpected(_:)` compares handshake messages, transcript hash, and split transport keys byte-for-byte against fixture expectations.
- `NoiseVectorRunner.verifyNegativeCase(_:in:)` applies mutation hooks (tamper/order) and asserts failure codes from fixture negative-case metadata.
- `cd ios && swift test --filter NoiseCoreTests` runs deterministic benchmark-oriented core tests
  that cover handshake patterns `NN`, `NK`, `KK`, `IK`, `XX` and built-in iOS suites
  (`25519` + `ChaChaPoly`/`AESGCM` + `SHA256`/`SHA512`), reporting per-variation and aggregate
  duration/throughput while still asserting correctness.

---

## 15. Cross-Platform Interop Verification Command

- Run `./scripts/verify-cross-platform-interop.sh` from the repository root.
- The command executes Android and iOS deterministic artifact checks against the same shared fixture contract and fails if either platform diverges on handshake messages, handshake hash, or split keys.
