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

### Changed

- Release workflow now enforces version parity before build/publish jobs.
- CI and release preflight now verify the tracked upstream Noise spec baseline before platform validation starts.
- Release process keeps publishing GitHub release bundles and `SHA256SUMS.txt` alongside package publication.
- GitHub Release now includes a direct `noise-protocol-<tag>.aar` asset in addition to archive bundles.
- Swift package manifests no longer use `unsafeFlags`, allowing downstream iOS apps to consume package targets.
- Android and iOS crypto/provider setup now reuses built-in stateless adapters and registries instead of rebuilding them for repeated suite or factory creation.
- Android Kotlin and iOS Swift handshake/HKDF/message-encoding paths now avoid several unnecessary short-lived buffer allocations.
- Cross-platform harness verification now checks fixture-expected artifacts on both Android and iOS, and benchmark documentation is refreshed from the current benchmark scripts.
- CI, release, and Swift package toolchain pins now target Java 21, Gradle 9.4.0, Xcode 16.4, and Swift tools 6.1.
- Android test dependencies now target JUnit 6.0.3, Android Gradle Plugin resolution now uses AGP 9.1.0 on Gradle 9 and AGP 8.13.2 on older Gradle lines, and GitHub Actions pins now track the current checkout/setup/upload/download major releases; Kotlin 2.3.10, kotlinx-serialization-json 1.10.0, the Maven Publish plugin, `softprops/action-gh-release@v2`, and `maxim-lobanov/setup-xcode@v1` were verified as already current.
- Android external dependency versions now live in `gradle/libs.versions.toml`, including AGP fallback pins, the Maven Publish plugin, and `kotlinx-serialization-json`, with settings/plugin resolution wired to that shared catalog.
- Android and iOS core handshake message APIs now enforce the Noise 65,535-byte message limit consistently, expose shared framed encoding helpers in core, and reuse those helpers from the Android test harness.
- The iOS core API now exposes handshake-hash access for channel binding and monotonic `NoiseCipherState.setNonce(_:)` control for out-of-order transport handling, matching existing Noise guidance and Android capabilities more closely.
- The iOS handshake session now exposes expected message direction and completion state so callers can drive strict Noise turn-taking explicitly, matching the Android handshake-state surface more closely.
- Android now exposes a `HandshakeSession` wrapper with framed read/write helpers, transcript-hash access, and handshake progress inspection so the Kotlin surface is closer to the Swift session API and easier to use correctly.
