#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
android_output="$(mktemp -d)"
ios_output="$(mktemp -d)"
trap 'rm -rf "$android_output" "$ios_output"' EXIT

compare_fixture() {
  local input_file="$1"
  local vector_file="$2"

  echo "[official-parity] Converting $(basename "$input_file") on Android..."
  "$repo_root/scripts/convert-official-noise-vectors.sh" "$input_file" "$android_output" >/dev/null

  echo "[official-parity] Converting $(basename "$input_file") on iOS..."
  "$repo_root/scripts/convert-official-noise-vectors-ios.sh" "$input_file" "$ios_output" >/dev/null

  local android_fixture="$android_output/$vector_file"
  local ios_fixture="$ios_output/$vector_file"

  if [[ ! -f "$android_fixture" || ! -f "$ios_fixture" ]]; then
    echo "[official-parity] Missing generated fixture for $(basename "$input_file")." >&2
    exit 1
  fi

  python3 - "$android_fixture" "$ios_fixture" <<'PY'
import json
import sys

android_path, ios_path = sys.argv[1], sys.argv[2]

with open(android_path, 'r', encoding='utf-8') as handle:
    android = json.load(handle)
with open(ios_path, 'r', encoding='utf-8') as handle:
    ios = json.load(handle)

keys_to_compare = [
    ("vector_id",),
    ("protocol",),
    ("inputs", "prologue"),
    ("inputs", "payloads"),
    ("inputs", "pre_shared_keys"),
    ("inputs", "key_material", "initiator", "static", "public"),
    ("inputs", "key_material", "initiator", "ephemeral", "public"),
    ("inputs", "key_material", "responder", "static", "public"),
    ("inputs", "key_material", "responder", "ephemeral", "public"),
    ("expected", "handshake_messages"),
    ("expected", "handshake_hash"),
    ("expected", "split_transport_keys"),
    ("negative_cases",),
]

def select(document, path):
    current = document
    for key in path:
        current = current.get(key) if isinstance(current, dict) else None
    return current

def normalize(path, value):
    if path == ("inputs", "pre_shared_keys") and value is None:
        return {}
    return value

for path in keys_to_compare:
    a_value = normalize(path, select(android, path))
    i_value = normalize(path, select(ios, path))
    if a_value != i_value:
        joined = '.'.join(path)
        print(f"Mismatch at {joined}\nAndroid: {a_value}\niOS: {i_value}", file=sys.stderr)
        sys.exit(1)
PY

  echo "[official-parity] $(basename "$input_file") parity passed."
}

compare_fixture "$repo_root/scripts/testdata/official-noise-nn-vector.json" "noise-nn-25519-chachapoly-sha256.json"
compare_fixture "$repo_root/scripts/testdata/official-noise-nn-448-vector.json" "noise-nn-448-chachapoly-sha256.json"
compare_fixture "$repo_root/scripts/testdata/official-noise-nnpsk0-vector.json" "noise-nnpsk0-25519-chachapoly-sha256.json"
compare_fixture "$repo_root/scripts/testdata/official-noise-xxpsk2-vector.json" "noise-xxpsk2-25519-chachapoly-sha256.json"

echo "[official-parity] Android and iOS official-vector conversion parity passed."