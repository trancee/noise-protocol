# Changelog

All notable changes to this project are documented in this file.

## SemVer policy

- The project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).
- `VERSION` is the canonical version source for Android, iOS, and release automation.

## [Unreleased]

### Added

- Pluggable cipher suite abstraction (`CipherSuite` struct in Swift, class in Kotlin) supporting 8 cipher suites:
  - `Noise_25519_ChaChaPoly_SHA256` (default — backward compatible)
  - `Noise_25519_ChaChaPoly_SHA512`
  - `Noise_25519_ChaChaPoly_BLAKE2s`
  - `Noise_25519_ChaChaPoly_BLAKE2b`
  - `Noise_25519_AESGCM_SHA256`
  - `Noise_25519_AESGCM_SHA512`
  - `Noise_25519_AESGCM_BLAKE2s`
  - `Noise_25519_AESGCM_BLAKE2b`
- AES-256-GCM cipher implementation (CryptoKit `AES.GCM` / JCA `AES/GCM/NoPadding`).
- SHA-512 hash implementation (CryptoKit `SHA512` / JCA `MessageDigest("SHA-512")`).
- BLAKE2s (32-byte, 10-round) and BLAKE2b (64-byte, 12-round) hash support via [`blake-hash`](https://github.com/trancee/blake-hash) library, with standard HMAC construction (RFC 2104).
- HASHLEN truncation for 64-byte hashes (SHA-512, BLAKE2b): `MixKey()` and `Split()` truncate HKDF output to 32 bytes for cipher keys per spec.
- 43 cross-platform test vectors: 8 cipher suites × 5 base patterns (NN, NK, KK, IK, XX) + 2 PSK patterns (NKpsk0, IKpsk2) for ChaChaPoly_SHA256 + 1 XXfallback — shared JSON files in `test-vectors/`, validated on both platforms.
- `HandshakeState` accepts optional `suite` parameter (defaults to ChaChaPoly_SHA256 for backward compatibility).
- Benchmark test suite for all cipher suites × patterns with transport throughput and XXfallback measurements.
- Comprehensive [BENCHMARK.md](BENCHMARK.md) with cross-platform results and performance analysis.

### Changed

- Replaced custom BLAKE2s/BLAKE2b implementations with [`blake-hash`](https://github.com/trancee/blake-hash) library (v1.1.0). Added as SPM dependency (iOS) and Maven Central dependency (Android). No API changes — all existing BLAKE2 cipher suites and test vectors are unaffected.

### Performance

- **iOS handshake ~22% faster**: cached DH public key computation, pre-allocated HKDF counter constants, optimized BLAKE2 HMAC ipad/opad loop, pre-sized handshake output buffer.
- **Android AES-GCM transport 2–3× faster**: `ThreadLocal<Cipher>` instance caching eliminates `Cipher.getInstance()` lookups on every encrypt/decrypt.
- **Android handshake buffer**: replaced repeated `ByteArray +=` concatenation with `ByteArrayOutputStream` to avoid per-token array copies.
- **Both platforms**: HKDF uses `System.arraycopy` / pre-allocated constants instead of allocating counter bytes on every call.

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
- 36 iOS tests (9 test vector + 27 unit) and 73 Android tests (42 parameterized test vector + 1 XXfallback + 30 unit).
- Cross-platform validation: identical output for same inputs on both platforms.
- Test vectors validated against cacophony and noise-c canonical outputs.
- Platform-specific README documentation with API reference and usage examples.
- `.claude/skills/` with Noise Protocol, Swift, and Android expert knowledge.
- `.github/copilot-instructions.md` for AI-assisted development guidance.

### Changed

- **BREAKING**: Simplified project structure from multi-module (noise-core, noise-crypto, noise-testing, noise-android on Android; NoiseCore, NoiseCryptoAdapters, NoiseTestHarness on iOS) to single-module per platform.
- **BREAKING**: Zero external dependencies — removed BigInt (iOS X448), BouncyCastle, and all third-party crypto adapters. Uses only CryptoKit (Swift) and JCA/JCE (Kotlin).
- **BREAKING**: Simplified API surface — single `HandshakeState` entry point replaces the previous multi-layer factory/adapter pattern.
- Default cipher suite is `Noise_*_25519_ChaChaPoly_SHA256`; pluggable via `CipherSuite` parameter.
- Swift package URL changed from tag-based multi-target to single `NoiseProtocol` target.

### Removed

- Multi-module project structure (noise-core, noise-crypto, noise-testing, noise-android).
- Pluggable crypto adapter registry and factory pattern.
- X448 cipher suite support (may return in a future minor release).
- Shared test-vector fixtures directory (`test-vectors/`) with JSON format and official vector conversion tooling removed; replaced with new cross-platform JSON vectors in [Unreleased].
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
