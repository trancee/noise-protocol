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
- Current v1 corpus includes the full base matrix plus representative PSK-backed fixtures (`82` fixtures total):
  - patterns: `NN`, `NK`, `KK`, `IK`, `XX`
  - DH: `25519`, `448`
  - ciphers: `ChaChaPoly`, `AESGCM`
  - hashes: `SHA256`, `SHA512`, `BLAKE2s`, `BLAKE2b`
- Additional representative PSK fixtures currently extend the shared contract with:
  - `Noise_NNpsk0_25519_ChaChaPoly_SHA256`
  - `Noise_XXpsk2_25519_ChaChaPoly_SHA256`
- Fixtures may optionally declare `inputs.pre_shared_keys` using `pskN` labels when the protocol name carries PSK modifiers.
- Fixture file naming for generated matrix vectors is:
  `noise-<pattern-lower>-<dh>-<cipher-lower>-<hash-lower>.json`

### 12.1 Mapping from the Official Noise Wiki Test-Vector Format

The upstream Noise wiki documents a conversation-oriented JSON format at:
`https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors`

That format is not consumed directly by this repository today. It is still the right reference for
understanding how Noise vectors are intended to drive a deterministic handshake and transport transcript.

Field mapping from the official wiki format to this repository's shared fixture format is:

- `protocol_name` -> `protocol.name`
- Handshake pattern portion of `protocol_name` -> `protocol.pattern`
- DH / cipher / hash portions of `protocol_name` -> `protocol.suite.{dh,cipher,hash}`
- `init_prologue` -> `inputs.prologue`
- `resp_prologue` -> must match `init_prologue` for the current shared fixture contract; the shared schema models one prologue value for both peers.
- `init_static` / `resp_static` -> `inputs.key_material.{initiator,responder}.static.private`
- Derived public keys for those private keys -> `inputs.key_material.{initiator,responder}.static.public`
- `init_ephemeral` / `resp_ephemeral` -> `inputs.key_material.{initiator,responder}.ephemeral.private`
- Derived public keys for those private keys -> `inputs.key_material.{initiator,responder}.ephemeral.public`
- `init_psks` / `resp_psks` -> `inputs.pre_shared_keys`, keyed as `psk0`, `psk1`, `psk2`, in protocol-name order
- `messages[*].payload` -> `inputs.payloads[*].plaintext_hex`
- Message sender is implicit in the wiki format's alternating order and becomes explicit in `inputs.payloads[*].sender`
- `messages[*].ciphertext` -> `expected.handshake_messages[*].message_hex` for handshake packets, and is also the basis for expected transport checks in transport-phase extensions
- `handshake_hash` -> `expected.handshake_hash`

There are also important format differences:

- The official wiki format is conversation-oriented. It models one alternating `messages` array that spans both handshake and transport traffic.
- This repository's shared schema is implementation-oriented. It separates deterministic inputs from expected outputs and additionally stores split transport keys under `expected.split_transport_keys`.
- The official wiki format allows `init_prologue` and `resp_prologue` to differ. The current shared contract assumes a single common `inputs.prologue` value.
- The official wiki format uses per-side PSK arrays. The current shared contract stores PSKs once by placement label because both peers must agree on the same values for a passing case.
- The official wiki format can represent fallback and hybrid-forward-secrecy metadata via `fallback`, `fallback_pattern`, and `hybrid`. The current shared v1 contract does not model those fields yet.
- The official wiki format does not make message direction explicit because it is implied by order. The shared contract stores `sender` explicitly so harnesses can validate direction and apply negative-case mutations more directly.

Practical usage guidance for this repository:

- Use the official wiki format as the normative reference for what a Noise vector means.
- Translate wiki vectors into the shared schema when adding cross-platform deterministic fixtures under `test-vectors/fixtures/v1/`.
- Derive and store both public keys and split transport keys during translation; those values are required by the local harnesses even though they are not primary fields in the wiki format.
- Do not treat official wiki fallback or hybrid vectors as directly importable into v1 fixtures; they currently require schema and harness extensions first.

Current compatibility status:

- Directly translatable today: standard deterministic base-pattern vectors and representative `pskN` vectors for currently supported patterns.
- Not directly representable today: official fallback vectors, hybrid-forward-secrecy vectors, and cases that rely on asymmetric initiator/responder prologues.
- The Android harness module now includes `OfficialNoiseVectorImporter`, which converts directly translatable official wiki vectors into in-memory shared v1 fixtures, derives missing local public keys from official private-key inputs, verifies handshake ciphertexts and handshake hashes against the official transcript, and synthesizes split transport keys plus standard negative cases for the local harness contract.
- Regression coverage now round-trips representative `Noise_NNpsk0_25519_ChaChaPoly_SHA256` and `Noise_XXpsk2_25519_ChaChaPoly_SHA256` fixtures through the importer, including both singular (`init_psk` / `resp_psk`) and plural (`init_psks` / `resp_psks`) official PSK field spellings.
- Imported key pairs follow the active DH adapter's normalization rules when deriving public keys from official private-key inputs, so private scalar bytes may be clamped relative to fixture seed material even when the resulting public keys and handshake artifacts match.
- Importer regression coverage also locks in the current rejection behavior for unsupported `hybrid` vectors, asymmetric initiator/responder prologues, and mismatched initiator/responder PSK value or count inputs.
- Importer regression coverage also locks in remote-static validation by rejecting `init_remote_static` or `resp_remote_static` values that do not match the derived local static public keys.
- Importer regression coverage also locks in transcript-integrity validation by rejecting mismatched official handshake `ciphertext` bytes and `handshake_hash` values.
- The Android harness module now also includes `OfficialNoiseVectorConverter`, which persists directly translatable official wiki vectors as canonical shared v1 fixture JSON files using `NoiseVectorFixtureWriter`.
- The Android module exposes this persisted conversion path through `:noise-testing:convertOfficialNoiseVectors`, using Gradle properties:
  `-PofficialNoiseInput=/absolute/path/to/official-vectors.json`
  `-PofficialNoiseOutput=/absolute/path/to/output-directory`
  optional `-PofficialNoiseSchema=../../schema/noise-vector-v1.schema.json`
- A repository wrapper script is also available at `scripts/convert-official-noise-vectors.sh`, with a smoke test in `scripts/test-convert-official-noise-vectors.sh` and sample official input in `scripts/testdata/official-noise-nn-vector.json`.
- That wrapper resolves repo-relative input and output paths before invoking the Android Gradle task, so it is safe to call from the repository root with relative paths.

---

## 13. Android Harness Usage

- Android module: `android/noise-testing`
- `NoiseVectorFixtureLoader` loads v1 fixtures directly from `test-vectors/fixtures/v1/`
- `NoiseVectorFixtureRepository` caches a loaded fixture corpus, supports lookup by `vector_id`, and filters by
  pattern / DH / cipher / hash so repeated deterministic runs do not re-parse the full corpus.
- `NoiseTestHarness.isSupported(...)` and `NoiseTestHarness.supportedFixtures(...)` expose provider-driven support discovery for fixture corpora.
- `NoiseTestHarness.runDeterministic(...)` coordinates deterministic `HandshakeState` execution with injected fixture key material
- `NoiseTestHarness.runDeterministic(repository, vectorId, ...)` resolves vectors from a cached repository for repeated runs
- `NoiseTestHarness.runNegativeCase(...)` applies fixture-driven mutation hooks (including tag tamper and handshake message-order mutations) and reports failures as harness results
- `NoiseTestHarness.runNegativeCase(repository, vectorId, caseId)` resolves both the fixture and negative-case from a cached repository
- `cd android && gradle --no-daemon :noise-core:test :noise-crypto:test --tests '*Benchmark*'`
  runs benchmark-oriented Android coverage (core handshake/transport and provider crypto variations)
  with correctness assertions

---

## 14. iOS Harness Integration

- `NoiseVectorFixtureLoader` loads shared fixtures from `test-vectors/fixtures/v1/` and decodes the v1 contract.
- `NoiseVectorFixtureRepository` caches the decoded iOS fixture corpus and supports lookup by `vector_id` plus
  filtering by pattern / DH / cipher / hash for repeated verification runs.
- `NoiseVectorRunner.supports(_:)` and `NoiseVectorRunner.supportedFixtures(repository:)` expose registry-driven support discovery for the shared fixture corpus.
- `NoiseVectorRunner.run(_:)` executes deterministic handshake orchestration using `NoiseCore` and crypto adapters selected from the fixture suite metadata.
- `NoiseVectorRunner.verifyExpected(_:)` compares handshake messages, transcript hash, and split transport keys byte-for-byte against fixture expectations.
- `NoiseVectorRunner.verifyExpected(repository:vectorID:)` resolves fixtures from the cached repository for repeated deterministic verification.
- `NoiseVectorRunner.verifyNegativeCase(_:in:)` applies mutation hooks (tamper/order) and asserts failure codes from fixture negative-case metadata.
- `NoiseVectorRunner.verifyNegativeCase(repository:vectorID:caseID:)` resolves both the fixture and negative-case from the cached repository.
- `cd ios && swift test --filter NoiseCoreTests` runs deterministic benchmark-oriented core tests
  that cover handshake patterns `NN`, `NK`, `KK`, `IK`, `XX` and built-in iOS suites
  (`25519` + `ChaChaPoly`/`AESGCM` + `SHA256`/`SHA512`), reporting per-variation and aggregate
  duration/throughput while still asserting correctness.

---

## 15. Cross-Platform Interop Verification Command

- Run `./scripts/verify-cross-platform-interop.sh` from the repository root.
- The command executes Android and iOS fixture-expected artifact checks against the baseline shared vector (`noise-nn-placeholder`) plus representative PSK-backed shared vectors (`noise-nnpsk0-25519-chachapoly-sha256` and `noise-xxpsk2-25519-chachapoly-sha256`) and fails if either platform diverges on handshake messages, handshake hash, or split keys.
