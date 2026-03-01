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

swift_manifests=(
  "$repo_root/Package.swift"
  "$repo_root/ios/Package.swift"
)

for swift_manifest in "${swift_manifests[@]}"; do
  if rg -q '\.unsafeFlags\(' "$swift_manifest"; then
    echo "[artifact-smoke] Swift manifest contains unsafeFlags and cannot be consumed as a package dependency: $swift_manifest" >&2
    exit 1
  fi
done

echo "[artifact-smoke] Building and publishing Android artifact to Maven local..."
(
  cd "$repo_root/android"
  gradle --no-daemon --console=plain :noise-protocol:publishToMavenLocal
)

maven_local_repo="${MAVEN_LOCAL_REPO:-$HOME/.m2/repository}"
android_artifact_dir="$maven_local_repo/ch/trancee/noise-protocol/$canonical_version"
android_metadata_file="$maven_local_repo/ch/trancee/noise-protocol/maven-metadata-local.xml"

required_android_files=(
  "noise-protocol-${canonical_version}.aar"
  "noise-protocol-${canonical_version}-sources.jar"
  "noise-protocol-${canonical_version}-javadoc.jar"
  "noise-protocol-${canonical_version}.pom"
)
expected_android_min_sdk=23

if [[ ! -d "$android_artifact_dir" ]]; then
  echo "[artifact-smoke] Missing published noise artifact directory: $android_artifact_dir" >&2
  exit 1
fi

for artifact in "${required_android_files[@]}"; do
  if [[ ! -f "$android_artifact_dir/$artifact" ]]; then
    echo "[artifact-smoke] Missing noise publication artifact: $android_artifact_dir/$artifact" >&2
    exit 1
  fi
done

if [[ ! -f "$android_metadata_file" ]]; then
  echo "[artifact-smoke] Missing noise publication metadata: $android_metadata_file" >&2
  exit 1
fi

if rg -q "<artifactId>noise-core</artifactId>" "$android_artifact_dir/noise-protocol-${canonical_version}.pom"; then
  echo "[artifact-smoke] Unexpected noise-core dependency in single-artifact POM." >&2
  exit 1
fi

if rg -q "<artifactId>noise-crypto</artifactId>" "$android_artifact_dir/noise-protocol-${canonical_version}.pom"; then
  echo "[artifact-smoke] Unexpected noise-crypto dependency in single-artifact POM." >&2
  exit 1
fi

if ! unzip -p "$android_artifact_dir/noise-protocol-${canonical_version}.aar" AndroidManifest.xml | rg -q "android:minSdkVersion=\"$expected_android_min_sdk\""; then
  echo "[artifact-smoke] Android AAR manifest does not declare minSdkVersion=$expected_android_min_sdk." >&2
  exit 1
fi

temp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$temp_dir"
}
trap cleanup EXIT

unzip -q "$android_artifact_dir/noise-protocol-${canonical_version}.aar" -d "$temp_dir"

if ! jar tf "$temp_dir/classes.jar" | rg -q "noise/protocol/android/NoiseAndroid.class"; then
  echo "[artifact-smoke] Missing NoiseAndroid marker class in classes.jar." >&2
  exit 1
fi

if ! compgen -G "$temp_dir/libs/*.jar" > /dev/null; then
  echo "[artifact-smoke] Missing embedded core/crypto jars under AAR libs/." >&2
  exit 1
fi

found_core_class=0
found_crypto_class=0
while IFS= read -r embedded_jar; do
  if jar tf "$embedded_jar" | rg -q "noise/protocol/core/HandshakeState.class"; then
    found_core_class=1
  fi
  if jar tf "$embedded_jar" | rg -q "noise/protocol/crypto/CryptoProvider.class"; then
    found_crypto_class=1
  fi
done < <(find "$temp_dir/libs" -type f -name "*.jar" -print)

if [[ "$found_core_class" -ne 1 ]]; then
  echo "[artifact-smoke] Embedded jars are missing noise-core classes." >&2
  exit 1
fi

if [[ "$found_crypto_class" -ne 1 ]]; then
  echo "[artifact-smoke] Embedded jars are missing noise-crypto classes." >&2
  exit 1
fi

echo "[artifact-smoke] Android single-artifact publication shape is valid."

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
