# Changelog

All notable changes to this project are documented in this file.

## SemVer policy

- The project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).
- `VERSION` is the canonical version source for Android, iOS, and release automation.

## [Unreleased]

## [2.0.2] — 2026-03-15

### Added

- Native C BLAKE2 implementation (`CBLAKE2` SPM target) for iOS — hash, HMAC, and HKDF run entirely in C with zero heap allocation, compiled with `-O3` for optimized ARM code.
- Native HKDF override path for BLAKE2 suites on iOS, eliminating intermediate `Data` allocations in `MixKey()` and `Split()`.

### Changed

- iOS BLAKE2 cipher suites now use the `CBLAKE2` C target instead of the pure-Swift `blake-hash` wrapper for hash, HMAC, and HKDF operations. The `blake-hash` SPM dependency is retained. Android continues to use the pure-Kotlin `blake-hash` library.

### Performance

- **iOS BLAKE2 handshakes 27–45% faster**: BLAKE2s and BLAKE2b suites now outperform SHA-256 suites on iOS thanks to the native C compression function and zero-allocation HMAC/HKDF path.

## [2.0.1] — 2026-03-15

### Fixed

- Upgraded maven-publish plugin to fix Central Portal deployment naming.
- Enabled Gradle configuration cache for faster Android builds.
- Removed unnecessary non-null assertions in Android tests.
- Enabled test logging to show standard output/error streams during test runs.

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
- Pluggable cipher suite abstraction (`CipherSuite` struct in Swift, class in Kotlin) supporting 8 cipher suites: ChaChaPoly and AESGCM × SHA-256, SHA-512, BLAKE2s, and BLAKE2b — all with X25519 DH.
- AES-256-GCM cipher implementation (CryptoKit `AES.GCM` / JCA `AES/GCM/NoPadding`).
- SHA-512 hash implementation (CryptoKit `SHA512` / JCA `MessageDigest("SHA-512")`).
- BLAKE2s (32-byte) and BLAKE2b (64-byte) hash support via [`blake-hash`](https://github.com/trancee/blake-hash) library (v1.1.0), with standard HMAC construction (RFC 2104).
- HASHLEN truncation for 64-byte hashes (SHA-512, BLAKE2b): `MixKey()` and `Split()` truncate HKDF output to 32 bytes for cipher keys per spec.
- 43 cross-platform test vectors: 8 cipher suites × 5 base patterns (NN, NK, KK, IK, XX) + 2 PSK patterns (NKpsk0, IKpsk2) for ChaChaPoly_SHA256 + 1 XXfallback — shared JSON files in `test-vectors/`.
- `HandshakeState` accepts optional `suite` parameter (defaults to ChaChaPoly_SHA256 for backward compatibility).
- Benchmark test suite for all cipher suites × patterns with transport throughput and XXfallback measurements.
- Comprehensive [BENCHMARK.md](BENCHMARK.md) with cross-platform results and performance analysis.

### Changed

- **BREAKING**: Simplified project structure from multi-module (noise-core, noise-crypto, noise-testing, noise-android on Android; NoiseCore, NoiseCryptoAdapters, NoiseTestHarness on iOS) to single-module per platform.
- **BREAKING**: Minimal external dependencies — removed BigInt (iOS X448), BouncyCastle, and all third-party crypto adapters. Uses CryptoKit (Swift) and JCA/JCE (Kotlin) for core crypto, plus [`blake-hash`](https://github.com/trancee/blake-hash) (v1.1.0) for BLAKE2 hashing.
- **BREAKING**: Simplified API surface — single `HandshakeState` entry point replaces the previous multi-layer factory/adapter pattern.
- Default cipher suite is `Noise_*_25519_ChaChaPoly_SHA256`; pluggable via `CipherSuite` parameter.
- Swift package URL changed from tag-based multi-target to single `NoiseProtocol` target.

### Removed

- Multi-module project structure (noise-core, noise-crypto, noise-testing, noise-android).
- Pluggable crypto adapter registry and factory pattern.
- X448 cipher suite support (may return in a future minor release).
- Shared test-vector fixtures directory (`test-vectors/`) with JSON format and official vector conversion tooling removed; replaced with new cross-platform JSON vectors.
- Benchmark infrastructure and documentation.
- v1 release automation scripts (`scripts/` directory — 11 validation/conversion scripts).
- `docs/` directory (7 technical documents).
- `test-vectors/` directory (shared fixtures and schema).
- `plan/` directory (feature implementation records).
- Root-level `Package.swift`, `Package.resolved`, `noise-spec.lock`, `AGENTS.md`.
- `noise-spec-watch.yml` workflow.
- Multi-module Gradle subprojects (noise-core, noise-crypto, noise-testing, noise-android).

### Performance

- **iOS handshake ~22% faster**: cached DH public key computation, pre-allocated HKDF counter constants, optimized BLAKE2 HMAC ipad/opad loop, pre-sized handshake output buffer.
- **Android AES-GCM transport 2–3× faster**: `ThreadLocal` caching of all JCA provider instances (`Cipher`, `MessageDigest`, `Mac`, `KeyPairGenerator`, `KeyFactory`, `KeyAgreement`) eliminates ~35 `getInstance()` provider lookups per handshake.
- **Android handshake 6–10% faster**: JCA provider caching removes per-call overhead from DH, hash, and HMAC operations.
- **Both platforms**: HKDF uses `System.arraycopy` / pre-allocated constants instead of allocating counter bytes on every call.

## [1.0.0] — 2026-03-08

Initial stable release. See [v1.0.0 tag](https://github.com/trancee/noise-protocol/releases/tag/v1.0.0) for details.
