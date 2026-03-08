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

### Changed

- Release workflow now enforces version parity before build/publish jobs.
- Release process keeps publishing GitHub release bundles and `SHA256SUMS.txt` alongside package publication.
- GitHub Release now includes a direct `noise-protocol-<tag>.aar` asset in addition to archive bundles.
- Swift package manifests no longer use `unsafeFlags`, allowing downstream iOS apps to consume package targets.
- Android and iOS crypto/provider setup now reuses built-in stateless adapters and registries instead of rebuilding them for repeated suite or factory creation.
- Android Kotlin and iOS Swift handshake/HKDF/message-encoding paths now avoid several unnecessary short-lived buffer allocations.
- Cross-platform harness verification now checks fixture-expected artifacts on both Android and iOS, and benchmark documentation is refreshed from the current benchmark scripts.
- CI, release, and Swift package toolchain pins now target Java 21, Gradle 9.4.0, Xcode 16.4, and Swift tools 6.1.
