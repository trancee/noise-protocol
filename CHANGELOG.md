# Changelog

All notable changes to this project are documented in this file.

## SemVer policy

- The project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).
- `VERSION` is the canonical version source for Android, iOS, and release automation.

## [Unreleased]

## [2.0.0] — 2026-03-13

Complete rewrite of both iOS and Android implementations with a simplified, zero-dependency architecture.

### Added

- Feature-complete Noise Protocol Framework implementation (revision 34) for iOS (Swift/CryptoKit) and Android (Kotlin/JCA).
- All 38+ handshake patterns: one-way (N, K, X), fundamental (NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX), deferred (23 patterns), PSK (psk0–pskN modifier), and fallback (XXfallback).
- Dynamic pattern lookup via `HandshakePattern.named()` on both platforms.
- PSK modifier support with `MixKeyAndHash` handling for arbitrary psk0–pskN placement.
- Injectable key generation via `KeyPairGenerator` protocol/interface for deterministic testing.
- Sealed error hierarchies (`NoiseError` in Swift, `NoiseException` in Kotlin) for exhaustive error handling.
- Handshake turn validation with `NotYourTurn` errors.
- Nonce exhaustion detection and 65,535-byte message limit enforcement.
- Proper nonce preservation on decryption failure per spec.
- Rekey support (`ENCRYPT(k, maxnonce, empty, zeros_32)`).
- 34 iOS tests (7 test vector + 27 unit) and 37 Android tests (7 test vector + 30 unit).
- Cross-platform validation: identical output for same inputs on both platforms.
- Test vectors validated against cacophony and noise-c canonical outputs.
- Platform-specific README documentation with API reference and usage examples.
- `.claude/skills/` with Noise Protocol, Swift, and Android expert knowledge.
- `.github/copilot-instructions.md` for AI-assisted development guidance.

### Changed

- **BREAKING**: Simplified project structure from multi-module (noise-core, noise-crypto, noise-testing, noise-android on Android; NoiseCore, NoiseCryptoAdapters, NoiseTestHarness on iOS) to single-module per platform.
- **BREAKING**: Zero external dependencies — removed BigInt (iOS X448), BouncyCastle, and all third-party crypto adapters. Uses only CryptoKit (Swift) and JCA/JCE (Kotlin).
- **BREAKING**: Simplified API surface — single `HandshakeState` entry point replaces the previous multi-layer factory/adapter pattern.
- Default cipher suite is now `Noise_*_25519_ChaChaPoly_SHA256` without pluggable crypto adapter registry.
- Swift package URL changed from tag-based multi-target to single `NoiseProtocol` target.

### Removed

- Multi-module project structure (noise-core, noise-crypto, noise-testing, noise-android).
- Pluggable crypto adapter registry and factory pattern.
- X448 and BLAKE2s/BLAKE2b cipher suite support (may return in a future minor release).
- Shared test-vector schema, fixtures directory, and official vector conversion tooling.
- Benchmark infrastructure and documentation.
- v1 release automation scripts (`scripts/` directory — 11 validation/conversion scripts).
- `docs/` directory (7 technical documents).
- `test-vectors/` directory (shared fixtures and schema).
- `plan/` directory (feature implementation records).
- Root-level `Package.swift`, `Package.resolved`, `noise-spec.lock`, `AGENTS.md`.
- `noise-spec-watch.yml` workflow.
- Multi-module Gradle subprojects (noise-core, noise-crypto, noise-testing, noise-android).

## [1.0.0] — 2026-03-08

Initial stable release. See [v1.0.0 tag](https://github.com/trancee/noise-protocol/releases/tag/v1.0.0) for details.
