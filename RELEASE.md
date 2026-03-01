# Release Runbook

This runbook documents the release flow implemented in `.github/workflows/release.yml`.

## 1) Prerequisites

### Tooling (for local preflight)

- Java 17
- Gradle 9.3.1
- Xcode 16.1
- Swift 6.0

### Repository settings and operator permissions

- You need permission to push tags (`v*`) and to run workflows (`workflow_dispatch`).
- Repository Actions settings must allow `GITHUB_TOKEN` write access, because the workflow creates GitHub releases.
- The workflow requests:
  - `contents: write` (release creation)

### Required secrets and publish inputs

| Name | Required | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` | Yes (workflow default secret) | Authenticates GitHub Release creation. |
| `MAVEN_CENTRAL_USERNAME` | Yes | Sonatype Central Portal token username used by Gradle publishing. |
| `MAVEN_CENTRAL_PASSWORD` | Yes | Sonatype Central Portal token password used by Gradle publishing. |
| `MAVEN_SIGNING_KEY` | Yes | ASCII-armored private PGP key used to sign Maven publications. |
| `MAVEN_SIGNING_PASSWORD` | Yes | Passphrase for `MAVEN_SIGNING_KEY`. |

Optional Gradle signing property: `signingInMemoryKeyId`.

## 2) Canonical version contract

- `VERSION` is the single source of truth for Android, iOS, and release automation.
- Android reads version from `../VERSION` (`android/build.gradle.kts`).
- Release tags must be `v<VERSION>`.
- Parity checks:
  - `bash ./scripts/verify-version-parity.sh`
  - `bash ./scripts/verify-version-parity.sh <tag>`

## 3) Preflight checks

Run these checks before creating the release trigger:

```bash
# Version parity
bash ./scripts/verify-version-parity.sh

# Android tests
cd android
gradle --no-daemon --console=plain :noise-core:test :noise-crypto:test :noise-testing:test
cd ..

# iOS tests
cd ios
swift test
cd ..

# Cross-platform deterministic interop
bash ./scripts/verify-cross-platform-interop.sh
```

Verify these repository secrets are present:
- `MAVEN_CENTRAL_USERNAME`
- `MAVEN_CENTRAL_PASSWORD`
- `MAVEN_SIGNING_KEY`
- `MAVEN_SIGNING_PASSWORD`

## 4) Version bump and changelog update

1. Update `VERSION` to the target release version (`MAJOR.MINOR.PATCH`).
2. Update `CHANGELOG.md` so release notes are ready before tagging.
3. Commit the release-prep changes on the branch/commit you will release.
4. Re-run `bash ./scripts/verify-version-parity.sh` after editing.

## 5) Trigger the release workflow

Use one of the two supported methods.

### Method A: tag push (default)

```bash
git tag v<VERSION>
git push origin v<VERSION>
```

This triggers `release.yml` via `on.push.tags: v*`.

### Method B: manual `workflow_dispatch`

1. Open **Actions → Release → Run workflow**.
2. Select the branch/commit to release.
3. Enter `tag` as `v<VERSION>`.
4. Run workflow.

For manual runs, the workflow uses the selected ref commit (`github.sha`) as `target_commitish`.

## 6) What the workflow publishes

If all jobs pass, the workflow publishes:

1. **Maven Central**  
   Artifacts:
   - `ch.trancee:noise-protocol:<VERSION>`  
   Task: `:noise-protocol:publishAndReleaseToMavenCentral`
2. **GitHub Release assets**
   - `noise-protocol-<tag>.tar.gz` (Android `noise-core`, `noise-crypto`, `noise-testing` JARs, plus AAR in archive)
   - `noise-protocol-<tag>.aar` (direct Android AAR asset)
   - `noise-ios-swiftpm-<tag>.tar.gz` (Swift package manifest + sources + `VERSION`)
   - `SHA256SUMS.txt` (generated from release `.tar.gz` and `.aar` assets)

## 7) Post-release verification checklist

- Workflow run is green for all jobs in `.github/workflows/release.yml`.
- GitHub Release exists for `v<VERSION>` with all assets above.
- `SHA256SUMS.txt` validates downloaded release archives.
- Maven Central contains `ch.trancee:noise-protocol:<VERSION>`.
- Consumers can resolve the new Android artifact version from Maven Central.

## 8) Failure handling and rollback

- If the workflow fails before publish jobs run, fix the issue and re-run.
- If Maven Central publish succeeds but a later release step fails, treat `<VERSION>` as consumed; prefer a new patch version and a new tag instead of reusing the same version.
- If GitHub Release creation fails after Maven Central publication, re-run only after confirming asset/version consistency.
- If the wrong tag was used and nothing was published, delete the tag and re-run with the correct tag.
- Do not force-overwrite a released version in Maven repositories; publish a new version instead.
