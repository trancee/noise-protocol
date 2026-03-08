# Noise Protocol Upstream Tracking

This repository tracks the upstream Noise specification with a versioned lock file so maintainers can detect spec drift before it turns into platform drift.

## Tracked baseline

- Spec: The Noise Protocol Framework
- Source: https://noiseprotocol.org/noise.html
- PDF: https://noiseprotocol.org/noise.pdf
- Revision: 34
- Date: 2018-07-11
- Status: official/unstable
- Last verified against the website: 2026-03-08

Machine-readable source of truth:

- `noise-spec.lock`

Verification commands:

- `bash ./scripts/test-verify-noise-spec-upstream.sh`
- `bash ./scripts/verify-noise-spec-upstream.sh`

Automation:

- CI and release preflight run `scripts/verify-noise-spec-upstream.sh`
- `.github/workflows/noise-spec-watch.yml` runs the check every Monday and on manual dispatch

## When the upstream site changes

1. Run `bash ./scripts/verify-noise-spec-upstream.sh` locally to confirm the mismatch.
2. Review the upstream HTML and PDF to determine whether the change is editorial, compatibility-affecting, or breaking.
3. Update `noise-spec.lock` and this document in the same pull request.
4. If the upstream change affects implementation, also update code, tests, vector fixtures, and developer-facing docs before merging.
5. Record the outcome in `CHANGELOG.md`.

## SemVer policy for upstream Noise changes

- No library version bump is required for a routine re-check when the upstream metadata still matches `noise-spec.lock`.
- Use a patch release when the response is documentation, automation, or non-behavioral test maintenance.
- Use a minor release when the upstream change requires additive, backward-compatible API or capability work.
- Use a major release when the upstream change requires a breaking API, wire-format, or interoperability change.

## Notes

- The lock file is versioned in git on purpose. It is the auditable record of which upstream Noise specification this repository targets.
- The iOS bootstrap surface still exposes revision 34 through `NoiseCoreVersion.specificationRevision`. If the tracked spec revision changes, update that API and its tests in the same pull request.