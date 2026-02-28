#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[interop] Running Android deterministic artifact parity test..."
(
  cd "$repo_root/android"
  gradle --no-daemon :noise-testing:test --console=plain \
    --tests dev.noiseprotocol.testing.NoiseTestHarnessTest.deterministicRunMatchesFixtureExpectedArtifacts
)

echo "[interop] Running iOS deterministic artifact parity test..."
(
  cd "$repo_root/ios"
  swift test --filter deterministicExecutionIsStableAcrossRuns
)

echo "[interop] Cross-platform deterministic fixture parity passed."
