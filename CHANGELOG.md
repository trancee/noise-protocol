# Changelog

All notable changes to this project are documented in this file.

## SemVer policy

- The project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).
- `VERSION` is the canonical version source for Android, iOS, and release automation.
- Release tags must use `v<VERSION>` and are validated by `scripts/verify-version-parity.sh`.
- Pre-release identifiers (for example `-SNAPSHOT`) are allowed while staging a release.

## [Unreleased]

### Added

- Canonical version contract wired across Android Gradle, iOS parity validation, and release workflows.
- Repository-root `Package.swift` entrypoint for Swift Package consumption from repository tags.
- Android `noise-protocol` publishable AAR module with Maven publication metadata.
- Release workflow job that publishes `ch.trancee:noise-protocol:<VERSION>` to Maven Central.
- Cached shared-fixture repository APIs for Android and iOS harnesses, including lookup by `vector_id` and support-discovery helpers for supported fixture corpora.
- Versioned upstream Noise spec lock file, parser regression script, and live website verification script.
- Weekly `Noise Spec Watch` GitHub Actions workflow for scheduled upstream spec drift checks.
- Developer guide for upstream Noise tracking and SemVer handling in `docs/Noise_Protocol_Upstream_Tracking.md`.
- Native iOS X448 implementation record in `plan/feature-ios-x448-support-1.md`, including the pinned `attaswift/BigInt` 5.7.0 dependency decision and the rollout/parity history for that work.

### Changed

- Release workflow now enforces version parity before build/publish jobs.
- CI and release preflight now verify the tracked upstream Noise spec baseline before platform validation starts.
- Android `noise-testing` now imports directly translatable official Noise wiki vectors into the shared v1 fixture contract, deriving local public keys from official private-key inputs and rejecting fallback, hybrid, and asymmetric-prologue cases that still need a future schema revision.
- Android official-vector importer regression coverage now round-trips representative `NNpsk0` and `XXpsk2` fixtures, supports singular and plural official PSK spellings, and locks in rejection behavior for unsupported `hybrid` vectors, asymmetric prologues, mismatched PSKs, mismatched remote-static hints, and mismatched official handshake `ciphertext` / `handshake_hash` values.
- Android `noise-testing` now includes `OfficialNoiseVectorConverter` and `NoiseVectorFixtureWriter` for persisting directly translatable official wiki vectors as canonical shared v1 fixture JSON files.
- Android `noise-testing` now exposes the official-vector conversion flow through `:noise-testing:convertOfficialNoiseVectors`, parameterized with Gradle properties for input, output, and optional schema path.
- Repository scripts now include `scripts/convert-official-noise-vectors.sh` plus a smoke test and sample official vector input for the persisted conversion flow.
- The repository conversion wrapper now normalizes repo-relative paths before invoking the Android Gradle conversion task.
- iOS `NoiseTestHarness` now includes an official Noise wiki converter and fixture writer for directly translatable built-in DH vectors (`25519` and `448`), with Swift Testing coverage for conversion and persistence.
- iOS now also exposes the official-vector conversion flow through `swift run NoiseVectorConverterCLI` and a repository wrapper script for repo-root usage.
- iOS official-vector conversion tests now also cover representative `NNpsk0` and `XXpsk2` vectors, including singular and plural official PSK field spellings.
- Native iOS X448 support now ships through `X448DiffieHellmanAdapter`, backed by the pinned `attaswift/BigInt` dependency and registered in the built-in crypto adapter registry.
- iOS crypto bootstrap tests now cover X448 shared-secret symmetry, deterministic public-key derivation from private bytes, and provider resolution for `diffieHellman: "448"`.
- iOS official-vector conversion regression coverage now also locks in rejection behavior for unsupported `hybrid` vectors, asymmetric prologues, mismatched PSK values or counts, mismatched remote-static hints, and mismatched official handshake `ciphertext` / `handshake_hash` values.
- iOS official-vector conversion now also round-trips a representative official `Noise_NN_448_ChaChaPoly_SHA256` sample into the canonical shared fixture contract.
- Cross-platform verification now includes `scripts/verify-official-vector-conversion-parity.sh` to compare Android and iOS outputs for representative official Noise inputs covering `NN`, `NN 448`, `NN BLAKE2s`, `NNpsk0`, and `XXpsk2`, with Android/iOS smoke tests and regression coverage pinned to the same canonical official-format inputs.
- iOS now ships built-in `BLAKE2s` and `BLAKE2b` hash/HKDF adapters, allowing the built-in registry and harness to execute the full shared 82-fixture corpus instead of the previous SHA-only subset.
- Cross-platform interop verification now also runs representative deterministic shared-fixture execution for both `Noise_NN_448_ChaChaPoly_SHA256` and `Noise_NN_25519_ChaChaPoly_BLAKE2s` on Android and iOS.
- `docs/Noise_Test_Harness.md` now maps the official Noise wiki test-vector format onto this repository's shared fixture schema and documents the current compatibility gaps for fallback, hybrid, and asymmetric-prologue vectors.
- Android and iOS cipher-state implementations now keep the current nonce unchanged when authenticated decryption fails, matching the Noise processing rules.
- Android and iOS core pattern tables, benchmarks, and bootstrap tests now cover all 12 fundamental interactive Noise handshake patterns, while the shared vector corpus remains on the current 5-pattern subset.
- Android and iOS core pattern tables, benchmarks, and bootstrap tests now also cover the one-way Noise patterns `N`, `K`, and `X`.
- Android and iOS core state machines now support `pskN` protocol-name modifiers for the currently supported base patterns, including `MixKeyAndHash()` handling and regression coverage for `psk0` and `psk2` flows.
- Android and iOS core protocol-name validation now rejects unsupported modifier grammar and base-pattern mismatches instead of silently treating them as plain patterns.
- Shared vector schema, Android/iOS harnesses, and cross-platform interop checks now carry optional `pre_shared_keys` input and validate representative `NNpsk0` and `XXpsk2` fixture artifacts from the canonical shared corpus.
- Release publishing now keeps GitHub release bundles and `SHA256SUMS.txt` alongside package publication, and GitHub Release also includes a direct `noise-protocol-<tag>.aar` asset.
- Swift package manifests no longer use `unsafeFlags`, allowing downstream iOS apps to consume package targets.
- Android and iOS crypto/provider setup now reuses built-in stateless adapters and registries instead of rebuilding them for repeated suite or factory creation, and handshake/HKDF/message-encoding paths now avoid several unnecessary short-lived buffer allocations.
- Cross-platform harness verification now checks fixture-expected artifacts on both Android and iOS, and benchmark documentation is refreshed from the current benchmark scripts.
- CI, release, and Swift package toolchain pins now target Java 21, Gradle 9.4.0, Xcode 16.4, and Swift tools 6.1; Android dependency/version management is consolidated through `gradle/libs.versions.toml`, with AGP 9.1.0 on Gradle 9 and AGP 8.13.2 on older Gradle lines, JUnit 6.0.3, Kotlin 2.3.10, `kotlinx-serialization-json` 1.10.0, the Maven Publish plugin, and current GitHub Actions pins verified in place.
- Android and iOS core handshake message APIs now enforce the Noise 65,535-byte message limit consistently, expose shared framed encoding helpers in core, and reuse those helpers from the Android test harness.
- The iOS and Android session surfaces now expose the handshake progress and transcript data needed for stricter turn-taking and transport control, including iOS handshake-hash access plus monotonic `NoiseCipherState.setNonce(_:)`, and an Android `HandshakeSession` wrapper with framed read/write helpers, transcript-hash access, and handshake progress inspection.
