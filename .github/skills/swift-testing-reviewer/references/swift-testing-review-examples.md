# Swift Testing Review Examples

Use these examples to keep review output focused on real testing risk instead of style noise.

## Strong Finding

Issue: The test only asserts that parsing returns three fields, but it never checks field contents. A regression that preserves count while corrupting quoted fields would still pass.

Why it matters: The current assertion does not protect the CSV behavior the test name claims to cover.

Better direction: Assert the exact parsed fields, especially the quoted-comma case that the parser is expected to preserve.

## Weak Finding

Issue: The test function name could be shorter.

Why this is weak: Naming is secondary unless it hides intent badly enough to impair diagnosis or maintenance. Do not lead with this when assertion strength or missing behavior coverage is the real risk.

## Strong Async Finding

Issue: The test sleeps for 0.5 seconds before checking cached state. This can still fail under scheduler variation and does not prove the awaited refresh boundary completed.

Why it matters: Timing-based waits create flaky behavior and can mask real race conditions.

Better direction: Await the actual async API or observe a deterministic state transition.

## Strong Parameterization Finding

Issue: The parameterized test mixes valid-format normalization cases with invalid-input rejection cases. The setup and expected outcomes differ enough that failures will be harder to diagnose.

Why it matters: Parameterization is only helping when one assertion shape covers all cases cleanly.

Better direction: Keep the normalization cases parameterized, but split rejection behavior into separately named tests.

## No-Findings Output Shape

If no meaningful findings exist, say so directly:

"No material issues found in the reviewed Swift Testing coverage. Assertions are behavior-oriented, async boundaries are deterministic, and the parameterized cases share one clear assertion shape. Residual risk: there is still no explicit regression test for malformed Unicode input."

## Review Output Pattern

1. Findings ordered by severity.
2. For each finding: current weakness, concrete risk, smallest useful improvement.
3. Open questions only where intent is unclear.
4. Brief residual-risk note at the end.
