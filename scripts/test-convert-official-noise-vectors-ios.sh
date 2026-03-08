#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temp_output="$(mktemp -d)"
trap 'rm -rf "$temp_output"' EXIT

echo "[official-convert-ios-test] Running iOS wrapper script against sample official vector..."
(
  cd "$repo_root"
  ./scripts/convert-official-noise-vectors-ios.sh "scripts/testdata/official-noise-nn-vector.json" "$temp_output"
)

output_file="$temp_output/noise-nn-25519-chachapoly-sha256.json"

if [[ ! -f "$output_file" ]]; then
  echo "[official-convert-ios-test] Expected output fixture missing: $output_file" >&2
  exit 1
fi

grep -q '"vector_id"[[:space:]]*:[[:space:]]*"noise-nn-25519-chachapoly-sha256"' "$output_file"
grep -q '"protocol"[[:space:]]*:[[:space:]]*{' "$output_file"
grep -q '"\$schema"[[:space:]]*:[[:space:]]*"..\\/..\\/schema\\/noise-vector-v1.schema.json"' "$output_file"

echo "[official-convert-ios-test] Wrapper script produced the expected shared fixture file."