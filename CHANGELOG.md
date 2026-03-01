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

### Changed

- Release workflow now enforces version parity before build/publish jobs.
- Release process keeps publishing GitHub release bundles and `SHA256SUMS.txt` alongside package publication.
- GitHub Release now includes a direct `noise-protocol-<tag>.aar` asset in addition to archive bundles.
- Swift package manifests no longer use `unsafeFlags`, allowing downstream iOS apps to consume package targets.
