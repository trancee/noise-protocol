#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temp_output="$(mktemp -d)"
trap 'rm -rf "$temp_output"' EXIT

echo "[official-convert-test] Running wrapper script against sample official vector..."
(
  cd "$repo_root"
  ./scripts/convert-official-noise-vectors.sh "scripts/testdata/official-noise-nn-vector.json" "$temp_output"
)

output_file="$temp_output/noise-nn-25519-chachapoly-sha256.json"

if [[ ! -f "$output_file" ]]; then
  echo "[official-convert-test] Expected output fixture missing: $output_file" >&2
  exit 1
fi

grep -q '"vector_id": "noise-nn-25519-chachapoly-sha256"' "$output_file"
grep -q '"protocol": {' "$output_file"
grep -q '"$schema": "../../schema/noise-vector-v1.schema.json"' "$output_file"

echo "[official-convert-test] Running wrapper script against representative official BLAKE2s vector..."
(
  cd "$repo_root"
  ./scripts/convert-official-noise-vectors.sh "scripts/testdata/official-noise-nn-blake2s-vector.json" "$temp_output/official-blake2s"
)

output_blake2s_file="$temp_output/official-blake2s/noise-nn-25519-chachapoly-blake2s.json"

if [[ ! -f "$output_blake2s_file" ]]; then
  echo "[official-convert-test] Expected BLAKE2s output fixture missing: $output_blake2s_file" >&2
  exit 1
fi

grep -q '"vector_id": "noise-nn-25519-chachapoly-blake2s"' "$output_blake2s_file"
grep -q '"hash": "BLAKE2s"' "$output_blake2s_file"

echo "[official-convert-test] Wrapper script produced the expected shared fixture file."