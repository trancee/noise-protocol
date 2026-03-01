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
- Android `noise-android-aar` publishable AAR module with Maven publication metadata.
- Release workflow job that publishes `noise.protocol:noise-android-aar:<VERSION>` to GitHub Packages (phase 1).

### Changed

- Release workflow now enforces version parity before build/publish jobs.
- Release process keeps publishing GitHub release bundles and `SHA256SUMS.txt` alongside package publication.
- Release workflow now skips external Maven upload when `MAVEN_REPOSITORY_*` secrets are missing, while continuing GitHub Packages and GitHub Release publication.
- GitHub Release now includes a direct `noise-android-aar-<tag>.aar` asset in addition to archive bundles.
