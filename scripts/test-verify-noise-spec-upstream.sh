#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$repo_root/scripts/verify-noise-spec-upstream.sh"
fixture="$repo_root/scripts/testdata/noise-spec-page-fixture.html"
tmp_fixture="$(mktemp)"
trap 'rm -f "$tmp_fixture"' EXIT

NOISE_SPEC_HTML_FILE="$fixture" bash "$script"

perl -0pe 's/Revision:\s*34/Revision: 35/' "$fixture" > "$tmp_fixture"

if NOISE_SPEC_HTML_FILE="$tmp_fixture" bash "$script" >/dev/null 2>&1; then
  echo "[noise-spec-test] Expected mismatch fixture to fail verification" >&2
  exit 1
fi

echo "[noise-spec-test] Parser and mismatch detection passed"