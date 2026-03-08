#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <official-vectors.json> <output-directory> [schema-path]" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
input_path="$1"
output_directory="$2"
schema_path="${3:-../../schema/noise-vector-v1.schema.json}"

input_path="$(cd "$(dirname "$input_path")" && pwd)/$(basename "$input_path")"
mkdir -p "$output_directory"
output_directory="$(cd "$output_directory" && pwd)"

echo "[official-convert] Converting $input_path into shared fixtures under $output_directory"
(
  cd "$repo_root/android"
  gradle --no-daemon :noise-testing:convertOfficialNoiseVectors --console=plain \
    -PofficialNoiseInput="$input_path" \
    -PofficialNoiseOutput="$output_directory" \
    -PofficialNoiseSchema="$schema_path"
)

echo "[official-convert] Conversion complete."