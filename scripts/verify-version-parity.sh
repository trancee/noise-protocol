#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
canonical_version_file="$repo_root/VERSION"
release_tag="${1:-}"

if [[ ! -f "$canonical_version_file" ]]; then
  echo "[version-parity] Missing canonical version file: $canonical_version_file" >&2
  exit 1
fi

canonical_version="$(head -n 1 "$canonical_version_file" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
if [[ -z "$canonical_version" ]]; then
  echo "[version-parity] Canonical version file is empty: $canonical_version_file" >&2
  exit 1
fi

echo "[version-parity] Canonical version: $canonical_version"

android_version="$(
  (
    cd "$repo_root/android"
    gradle --no-daemon --quiet --console=plain properties --property version
  ) | awk -F': ' '/^version: / { print $2 }' | tail -n 1 | tr -d '\r'
)"

if [[ -z "$android_version" ]]; then
  echo "[version-parity] Failed to read Android version." >&2
  exit 1
fi
if [[ "$android_version" != "$canonical_version" ]]; then
  echo "[version-parity] Android version mismatch: canonical=$canonical_version android=$android_version" >&2
  exit 1
fi

echo "[version-parity] Android version matches canonical source."

echo "[version-parity] Verifying iOS version surface..."
(
  cd "$repo_root/ios"
  swift test --filter bootstrapLibraryVersion >/dev/null
)

if [[ -n "$release_tag" ]]; then
  if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
    echo "[version-parity] Release tag has invalid format: $release_tag" >&2
    exit 1
  fi
  tag_version="${release_tag#v}"
  if [[ "$tag_version" != "$canonical_version" ]]; then
    echo "[version-parity] Release tag mismatch: canonical=$canonical_version tag=$release_tag" >&2
    exit 1
  fi
  echo "[version-parity] Release tag matches canonical version."
fi

echo "[version-parity] Version parity checks passed."
