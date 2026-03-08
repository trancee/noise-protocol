---
goal: Native iOS X448 support for Noise crypto providers and official vector conversion
version: 1.0
date_created: 2026-03-08
last_updated: 2026-03-08
owner: GitHub Copilot
status: 'Completed'
tags: [feature, ios, crypto, x448, noise, interoperability]
---

# Introduction

![Status: Completed](https://img.shields.io/badge/status-Completed-brightgreen)

This plan records the work completed to add native iOS X448 support to the Noise crypto adapter layer, the shared-fixture harness, and the official wiki vector conversion flow. iOS now supports both `25519` and `448`. Android already included an in-repository X448 Montgomery ladder implementation, and that behavior served as the internal parity reference during rollout.

Phase 1 decision update:
- Prefer a pinned pure-Swift bigint dependency via `attaswift/BigInt` for the first implementation pass.
- Do not use `apple/swift-numerics` for this gap; its published modules do not provide arbitrary-precision integers.
- Revisit a dependency-free limb implementation only if the pinned dependency proves incompatible with package-consumer requirements or produces unacceptable performance/regression risk.

## 1. Requirements & Constraints

- **REQ-001**: iOS must support `NoiseVectorDiffieHellman.x448` end to end in `NoiseCryptoAdapters`, `NoiseCore`, `NoiseTestHarness`, and official-vector conversion.
- **REQ-002**: The iOS X448 implementation must interoperate byte-for-byte with the existing Android `X448DiffieHellmanAdapter` in `android/noise-crypto/src/main/kotlin/noise/protocol/crypto/DiffieHellmanAdapters.kt`.
- **REQ-003**: iOS official Noise wiki vector conversion must accept directly translatable official `448` vectors once X448 support exists.
- **REQ-004**: Existing `25519` behavior, CLI wrappers, and shared-fixture parity checks must remain unchanged.
- **CON-001**: CryptoKit does not expose X448 primitives, so iOS cannot rely on current built-in Apple APIs for this feature.
- **CON-002**: Swift has no built-in arbitrary-precision integer type comparable to Java `BigInteger`, so a direct source translation of the Android implementation requires either a new bigint dependency or a limb-based field implementation.
- **CON-003**: Any dependency added for X448 must be pin-safe in SwiftPM and must not break downstream package consumption.
- **GUD-001**: Prefer a self-contained, auditable implementation or a well-maintained package with explicit version pinning over opaque binary distribution.
- **GUD-002**: Keep the current explicit unsupported-`448` test coverage until native support lands; remove it only in the same change set that adds full positive coverage.
- **PAT-001**: Preserve the existing adapter registry pattern in `ios/Sources/NoiseCryptoAdapters/NoiseCryptoAdapters.swift` by registering X448 through `NoiseCryptoAdapterRegistry` rather than special-casing it in callers.
- **PAT-002**: Preserve the shared-fixture contract in `test-vectors/schema/noise-vector-v1.schema.json`; do not create iOS-specific fixture shapes.

## 2. Implementation Steps

### Implementation Phase 1

- **GOAL-001**: Select and pin the iOS X448 arithmetic strategy. Completed.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-001 | Evaluate whether to implement X448 with a new SwiftPM bigint dependency or with a limb-based field implementation under `ios/Sources/NoiseCryptoAdapters/`. Recommendation selected: use `attaswift/BigInt` as the preferred bigint dependency candidate and reject `apple/swift-numerics` for this purpose because it does not provide arbitrary-precision integers. | ✅ | 2026-03-08 |
| TASK-002 | If a dependency is required, update `ios/Package.swift` and any lockfile state with an exact pinned version and verify downstream package compatibility from the repository-root `Package.swift`. Completed by pinning `attaswift/BigInt` to `5.7.0` in both SwiftPM entrypoints (`ios/Package.swift` and the repository-root `Package.swift`) to keep package-consumer resolution aligned before the adapter code lands. | ✅ | 2026-03-08 |
| TASK-003 | Document the selected arithmetic strategy and rejection of alternatives in `docs/Noise_Crypto_Adapters.md` and `CHANGELOG.md`. | ✅ | 2026-03-08 |

### Implementation Phase 2

- **GOAL-002**: Implement and register a native iOS X448 adapter. Completed.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-004 | Add `X448DiffieHellmanAdapter` to `ios/Sources/NoiseCryptoAdapters/NoiseCryptoAdapters.swift` or a new adjacent source file, matching the `NoiseDiffieHellmanAdapter` contract and using `name = "448"`. Completed by adding `ios/Sources/NoiseCryptoAdapters/X448DiffieHellmanAdapter.swift` plus deterministic private-key derivation support for official-vector conversion. | ✅ | 2026-03-08 |
| TASK-005 | Implement X448 scalar clamping, base-point multiplication, and shared-secret derivation so that generated public keys and `dh(private, public)` outputs match Android parity artifacts. | ✅ | 2026-03-08 |
| TASK-006 | Register the adapter in `NoiseCryptoAdapterRegistry.builtInDiffieHellmanAdapters` so provider construction for `diffieHellman: "448"` succeeds without caller changes. | ✅ | 2026-03-08 |

### Implementation Phase 3

- **GOAL-003**: Extend iOS fixture and official-vector flows to positive `448` support. Completed.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-007 | Update `ios/Sources/NoiseTestHarness/OfficialNoiseVectorConversion.swift` so protocol parsing accepts `448` and key derivation routes through the registered X448 adapter instead of the current Curve25519-only path. | ✅ | 2026-03-08 |
| TASK-008 | Remove the explicit unsupported-`448` rejection path and replace it with positive conversion for official `448` vectors using `NoiseVectorRunner`. | ✅ | 2026-03-08 |
| TASK-009 | Extend `scripts/convert-official-noise-vectors-ios.sh` and `scripts/test-convert-official-noise-vectors-ios.sh` so the wrapper succeeds for a representative official `448` sample after support is added. | ✅ | 2026-03-08 |

### Implementation Phase 4

- **GOAL-004**: Add parity, regression, and interop verification for iOS X448. Completed.

| Task | Description | Completed | Date |
|------|-------------|-----------|------|
| TASK-010 | Add unit tests in `ios/Tests/NoiseCryptoAdaptersTests/NoiseCryptoAdaptersBootstrapTests.swift` for X448 shared-secret symmetry, public-key derivation from private bytes, and registry/provider resolution. | ✅ | 2026-03-08 |
| TASK-011 | Add positive harness coverage in `ios/Tests/NoiseTestHarnessTests/OfficialNoiseVectorConversionTests.swift` for representative official `Noise_NN_448_ChaChaPoly_SHA256` conversion and persistence. | ✅ | 2026-03-08 |
| TASK-012 | Extend cross-platform parity tooling, including `scripts/verify-official-vector-conversion-parity.sh`, to compare Android and iOS outputs for at least one representative official `448` sample. | ✅ | 2026-03-08 |

## 3. Alternatives

- **ALT-001**: Continue rejecting official `448` vectors on iOS indefinitely. Rejected because the shared fixture corpus and Android already support `448`, so iOS remains the only platform gap.
- **ALT-002**: Use `apple/swift-numerics` as the arithmetic foundation. Rejected because its published modules do not provide arbitrary-precision integers; its roadmap lists arbitrary-precision integers only as future expansion.
- **ALT-003**: Bridge to a binary-only native dependency for X448. Rejected unless no auditable SwiftPM-compatible alternative exists, because it weakens portability and reviewability.
- **ALT-004**: Port the Android `BigInteger`-based X448 implementation line-for-line to Swift without a bigint layer. Rejected as the first implementation pass because Swift lacks a built-in arbitrary-precision integer type, so a direct translation is not practical without adding significant new arithmetic infrastructure.

## 4. Dependencies

- **DEP-001**: Preferred dependency candidate: `attaswift/BigInt` (pure Swift, SwiftPM-compatible, MIT licensed). Fallback only if needed: a new in-repo limb-based finite-field implementation for the X448 prime field.
- **DEP-002**: Existing iOS adapter registry and factory surfaces in `ios/Sources/NoiseCryptoAdapters/NoiseCryptoAdapters.swift`.
- **DEP-003**: Existing Android reference behavior in `android/noise-crypto/src/main/kotlin/noise/protocol/crypto/DiffieHellmanAdapters.kt` for parity validation.

## 5. Files

- **FILE-001**: `ios/Sources/NoiseCryptoAdapters/NoiseCryptoAdapters.swift` for adapter registration and possibly the X448 adapter implementation.
- **FILE-002**: `ios/Sources/NoiseTestHarness/OfficialNoiseVectorConversion.swift` for official `448` vector acceptance and key derivation.
- **FILE-003**: `ios/Tests/NoiseCryptoAdaptersTests/NoiseCryptoAdaptersBootstrapTests.swift` for X448 crypto adapter tests.
- **FILE-004**: `ios/Tests/NoiseTestHarnessTests/OfficialNoiseVectorConversionTests.swift` for official `448` positive conversion coverage.
- **FILE-005**: `scripts/convert-official-noise-vectors-ios.sh` and `scripts/test-convert-official-noise-vectors-ios.sh` for wrapper behavior.
- **FILE-006**: `scripts/verify-official-vector-conversion-parity.sh` for cross-platform official `448` parity.
- **FILE-007**: `docs/Noise_Crypto_Adapters.md`, `docs/Noise_Test_Harness.md`, and `CHANGELOG.md` for developer-facing documentation and versioned change notes.

## 6. Testing

- **TEST-001**: Verify X448 public-key derivation from deterministic private bytes matches Android reference outputs.
- **TEST-002**: Verify X448 shared-secret symmetry between two generated key pairs on iOS.
- **TEST-003**: Verify `NoiseCryptoAdapterFactory` constructs providers for `diffieHellman: "448"` without unsupported-DH failures.
- **TEST-004**: Verify representative shared fixtures with `suite.dh = .x448` execute successfully in `NoiseVectorRunner`.
- **TEST-005**: Verify official `448` vector conversion on iOS produces the same shared-fixture semantics as Android for a representative sample.
- **TEST-006**: Run `cd ios && swift test` plus `./scripts/verify-official-vector-conversion-parity.sh` and `./scripts/verify-cross-platform-interop.sh` after support lands.

## 7. Risks & Assumptions

- **RISK-001**: Introducing bigint arithmetic or a new crypto dependency can increase package size, build time, and security review surface.
- **RISK-002**: A custom X448 implementation may be functionally correct but not constant-time if translated carelessly.
- **RISK-003**: Divergence from Android clamping or ladder behavior will surface as official-vector and shared-fixture parity failures.
- **ASSUMPTION-001**: The Android `X448DiffieHellmanAdapter` is the current in-repo correctness baseline for cross-platform parity.
- **ASSUMPTION-002**: The existing shared v1 schema is sufficient for `448` once the iOS crypto layer can derive keys and execute the handshake.

## 8. Related Specifications / Further Reading

- `docs/Noise_Crypto_Adapters.md`
- `docs/Noise_Test_Harness.md`
- `docs/Noise_Protocol_Implementation_Plan.md`
- `android/noise-crypto/src/main/kotlin/noise/protocol/crypto/DiffieHellmanAdapters.kt`
- `ios/Sources/NoiseCryptoAdapters/NoiseCryptoAdapters.swift`