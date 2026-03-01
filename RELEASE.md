# Build Instructions (Release Operations)

This document reflects the currently implemented build and release flow.

## Canonical version contract

- `VERSION` is the single version source for Android, iOS, and release automation.
- Android reads the canonical version from `../VERSION` in `android/build.gradle.kts`.
- CI and release enforce parity with:
  - `bash ./scripts/verify-version-parity.sh`
  - `bash ./scripts/verify-version-parity.sh <tag>`
- Release tags must be `v<VERSION>`.

## Operator prerequisites and secrets

### Tooling

- Java 17
- Gradle 8.10.2
- Xcode 16.1 / Swift 6.0

### GitHub Actions permissions

- `contents: write` (release creation)
- `packages: write` (GitHub Packages publish job)

### Required publish environment

- `GITHUB_ACTOR`
- `GITHUB_TOKEN`
  - In GitHub Actions this is `${{ secrets.GITHUB_TOKEN }}`
  - For local publishing use a token with package write access
- `GITHUB_PACKAGES_URL` (optional override; defaults to `https://maven.pkg.github.com/<owner>/<repo>`)
- `MAVEN_REPOSITORY_URL` (for additional Maven repository publish)
- `MAVEN_REPOSITORY_USERNAME`
- `MAVEN_REPOSITORY_PASSWORD`

### Optional signing inputs (Gradle properties)

- `signingKeyId`
- `signingKey`
- `signingPassword`

If signing values are absent, publication still proceeds (current phase-1 behavior).

## Implemented CI flow (`.github/workflows/ci.yml`)

1. Version parity gate (`scripts/verify-version-parity.sh`)
2. Android tests (`:noise-core:test :noise-crypto:test :noise-testing:test`)
3. iOS tests (`swift test` in `ios/`)
4. Cross-platform interop (`scripts/verify-cross-platform-interop.sh`)

## Implemented release flow (`.github/workflows/release.yml`)

1. Resolve `RELEASE_TAG` from tag push or manual dispatch input.
2. Run version parity checks against `VERSION` and `RELEASE_TAG`.
3. Build/test Android and package release JAR bundle:
   - `noise-core`, `noise-crypto`, `noise-testing`
   - output: `noise-android-<tag>.tar.gz`
4. Build/test Swift package and package iOS source bundle:
   - output: `noise-ios-swiftpm-<tag>.tar.gz`
5. Publish `noise.protocol:noise-android-aar:<VERSION>` to GitHub Packages:
   - `:noise-android-aar:publishReleasePublicationToGitHubPackagesRepository`
6. Publish `noise.protocol:noise-android-aar:<VERSION>` to external Maven repository:
   - `:noise-android-aar:publishReleasePublicationToExternalMavenRepository`
7. Generate `SHA256SUMS.txt` and create GitHub Release.

## Local operator commands

```bash
# Verify version contract
bash ./scripts/verify-version-parity.sh

# Android validation and local publish smoke check
cd android
gradle --no-daemon --console=plain :noise-core:test :noise-crypto:test :noise-testing:test
gradle --no-daemon --console=plain :noise-android-aar:assembleRelease :noise-android-aar:publishReleasePublicationToMavenLocal

# Optional: publish to GitHub Packages (phase 1 target)
GITHUB_ACTOR=<user> \
GITHUB_TOKEN=<token> \
GITHUB_PACKAGES_URL=https://maven.pkg.github.com/<owner>/<repo> \
gradle --no-daemon --console=plain :noise-android-aar:publishReleasePublicationToGitHubPackagesRepository

# Optional: publish to external Maven repository
MAVEN_REPOSITORY_URL=https://maven.example.com/releases \
MAVEN_REPOSITORY_USERNAME=<user> \
MAVEN_REPOSITORY_PASSWORD=<password> \
gradle --no-daemon --console=plain :noise-android-aar:publishReleasePublicationToExternalMavenRepository
cd ..

# iOS and interop verification
swift test
bash ./scripts/verify-cross-platform-interop.sh
```

## Distribution notes

- Android publication targets: GitHub Packages and configured external Maven repository (`noise-android-aar`).
- GitHub Releases continue to publish tarballs plus checksums.
- Maven Central publication remains a future phase.
