#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock_file="$repo_root/noise-spec.lock"

if [[ ! -f "$lock_file" ]]; then
  echo "[noise-spec] Missing tracked lock file: $lock_file" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$lock_file"

if [[ -n "${NOISE_SPEC_HTML_FILE:-}" ]]; then
  if [[ ! -f "$NOISE_SPEC_HTML_FILE" ]]; then
    echo "[noise-spec] Fixture file does not exist: $NOISE_SPEC_HTML_FILE" >&2
    exit 1
  fi
  html_source="$NOISE_SPEC_HTML_FILE"
  html_content="$(cat "$NOISE_SPEC_HTML_FILE")"
else
  html_source="$NOISE_SPEC_URL"
  html_content="$(curl --fail --silent --show-error --location "$NOISE_SPEC_URL")"
fi

normalized_html="$({ printf '%s' "$html_content" | tr '\r\n' ' ' | sed 's/[[:space:]]\+/ /g'; printf '\n'; })"
normalized_text="$({ printf '%s' "$html_content" | sed 's/<[^>]*>/ /g' | tr '\r\n' ' ' | sed 's/[[:space:]]\+/ /g'; printf '\n'; })"

extract_field() {
  local pattern="$1"
  perl -0ne "if (m{$pattern}) { print \$1; }" <<<"$normalized_text"
}

current_revision="$(extract_field 'Revision:\s*([0-9]+)')"
current_date="$(extract_field 'Date:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})')"
current_status="$(extract_field 'Status:\s*([A-Za-z0-9/_-]+)')"

if [[ -z "$current_revision" || -z "$current_date" || -z "$current_status" ]]; then
  echo "[noise-spec] Failed to parse spec metadata from $html_source" >&2
  exit 1
fi

if ! grep -Eq 'noise\.pdf|https://noiseprotocol\.org/noise\.pdf' <<<"$normalized_html"; then
  echo "[noise-spec] Failed to locate expected Noise PDF reference in $html_source" >&2
  exit 1
fi

echo "[noise-spec] Tracked revision: $NOISE_SPEC_REVISION ($NOISE_SPEC_DATE, $NOISE_SPEC_STATUS)"
echo "[noise-spec] Upstream revision: $current_revision ($current_date, $current_status)"

if [[ "$current_revision" != "$NOISE_SPEC_REVISION" || "$current_date" != "$NOISE_SPEC_DATE" || "$current_status" != "$NOISE_SPEC_STATUS" ]]; then
  echo "[noise-spec] Upstream Noise spec metadata differs from noise-spec.lock" >&2
  exit 1
fi

echo "[noise-spec] Upstream Noise spec metadata matches noise-spec.lock"