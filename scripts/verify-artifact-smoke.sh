#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
canonical_version_file="$repo_root/VERSION"

if [[ ! -f "$canonical_version_file" ]]; then
  echo "[artifact-smoke] Missing canonical version file: $canonical_version_file" >&2
  exit 1
fi

canonical_version="$(head -n 1 "$canonical_version_file" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
if [[ -z "$canonical_version" ]]; then
  echo "[artifact-smoke] Canonical version file is empty: $canonical_version_file" >&2
  exit 1
fi

echo "[artifact-smoke] Verifying release version parity contract..."
bash "$repo_root/scripts/verify-version-parity.sh"

echo "[artifact-smoke] Building and publishing Android AAR to Maven local..."
(
  cd "$repo_root/android"
  gradle --no-daemon --console=plain :noise-android-aar:publishReleasePublicationToMavenLocal
)

maven_local_repo="${MAVEN_LOCAL_REPO:-$HOME/.m2/repository}"
android_artifact_dir="$maven_local_repo/noise/protocol/noise-android-aar/$canonical_version"
android_metadata_file="$maven_local_repo/noise/protocol/noise-android-aar/maven-metadata-local.xml"

required_android_files=(
  "noise-android-aar-${canonical_version}.aar"
  "noise-android-aar-${canonical_version}-sources.jar"
  "noise-android-aar-${canonical_version}-javadoc.jar"
  "noise-android-aar-${canonical_version}.pom"
)

if [[ ! -d "$android_artifact_dir" ]]; then
  echo "[artifact-smoke] Missing published Android artifact directory: $android_artifact_dir" >&2
  exit 1
fi

for artifact in "${required_android_files[@]}"; do
  if [[ ! -f "$android_artifact_dir/$artifact" ]]; then
    echo "[artifact-smoke] Missing Android publication artifact: $android_artifact_dir/$artifact" >&2
    exit 1
  fi
done

if [[ ! -f "$android_metadata_file" ]]; then
  echo "[artifact-smoke] Missing Android publication metadata: $android_metadata_file" >&2
  exit 1
fi

echo "[artifact-smoke] Android AAR publication shape is valid."

echo "[artifact-smoke] Resolving/building/testing root Swift package..."
(
  cd "$repo_root"
  swift package resolve
  swift build
  swift test
)

echo "[artifact-smoke] Resolving/building/testing legacy ios/Package.swift..."
(
  cd "$repo_root/ios"
  swift package resolve
  swift build
  swift test
)

echo "[artifact-smoke] Artifact smoke validation passed."
