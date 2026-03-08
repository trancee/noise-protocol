#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[interop] Running Android deterministic artifact parity test..."
(
  cd "$repo_root/android"
  gradle --no-daemon :noise-testing:test --console=plain \
    --tests noise.protocol.testing.NoiseTestHarnessTest.deterministicRunMatchesFixtureExpectedArtifacts \
    --tests noise.protocol.testing.NoiseTestHarnessTest.deterministicRunMatchesExpectedArtifactsForRepresentativePskFixtures
)

echo "[interop] Running iOS deterministic artifact parity test..."
(
  cd "$repo_root/ios"
  swift test --filter deterministicExecutionMatchesExpectedArtifactsForSharedVector
  swift test --filter deterministicExecutionMatchesExpectedArtifactsForRepresentativePskFixtures
)

echo "[interop] Cross-platform deterministic fixture parity passed."
