---
name: swift-testing-reviewer
description: 'Review and improve Apple Swift Testing code in Swift packages and Xcode projects. Use when asked to audit tests, find weak assertions, identify missing edge cases, tighten parameterized coverage, remove flaky async patterns, assess tags or traits, or suggest stronger Swift Testing structure using @Test, @Suite, #expect, #require, async tests, and regression coverage.'
argument-hint: 'What test file, suite, or testing problem should be reviewed?'
user-invocable: true
---

# Swift Testing Reviewer

Use this skill to review existing Swift Testing code and recommend or implement targeted improvements. Prefer it when the user wants findings, risks, and concrete changes rather than brand-new test coverage from scratch.

Load [Swift Testing review checklist](./references/swift-testing-review-checklist.md) when you need a compact rubric for assertions, case selection, async behavior, metadata, and regression coverage.
Load [Swift Testing review examples](./references/swift-testing-review-examples.md) when you need examples of strong findings, weak findings, and behavior-focused review output.

## When to Use This Skill

- The user asks for a review of existing Swift tests.
- A test suite feels flaky, weak, redundant, or hard to diagnose.
- Parameterized coverage may be too broad, too narrow, or poorly structured.
- Async tests appear to rely on sleeps, race-prone sequencing, or incidental timing.
- The user wants gaps, risks, and missing coverage identified before more tests are added.

## When Not to Use This Skill

- The user wants a new test written from scratch with little or no existing test code to evaluate.
- The task is primarily migrating XCTest to Swift Testing; use a migration workflow instead.
- The request is about CI, build graph, simulator setup, or general infrastructure rather than test quality.
- The target area has not adopted Swift Testing and the user has not asked to introduce it.

## Before Reviewing

Ask these questions before judging the test code:

- What user-visible or caller-visible behavior is this suite supposed to protect?
- Which failures would be expensive or easy to miss in production?
- Is the suite trying to prove behavior, or is it mostly mirroring implementation details?
- Which tests are most likely to become flaky under parallel execution or timing variation?

## Workflow

### 1. Identify The Review Surface

1. Determine whether the user wants a file review, suite review, bug-focused review, or broader quality audit.
2. Read the nearby production code only as needed to understand intended behavior.
3. Check whether the reviewed area already follows local Swift Testing conventions.

### 2. Evaluate Behavioral Coverage

1. Map each test to the behavior it claims to protect.
2. Flag gaps where important happy-path, edge-case, error-path, or regression coverage is missing.
3. Distinguish missing behavior coverage from mere naming or style preferences.

### 3. Evaluate Test Strength

- Check whether assertions would actually fail on the intended regression.
- Look for tests that only assert non-nil values, counts, or incidental state when stronger behavior assertions are possible.
- Check whether `#require(...)` is used only where later assertions would otherwise become noisy or misleading.
- Check whether parameterized cases share one assertion shape and expose failures clearly.

### 4. Evaluate Reliability And Maintainability

1. Flag sleeps, timing guesses, hidden shared state, and order-dependent setup.
2. Check whether helpers or fixtures obscure the behavior being tested.
3. Check whether tags, traits, attachments, or bug references have a concrete operational purpose.
4. Prefer small, behavior-oriented improvements over stylistic rewrites.

### 5. Report And Improve

1. Present findings first, ordered by severity.
2. Include the concrete risk or likely regression each finding leaves exposed.
3. Suggest or implement the smallest change that materially strengthens the test.
4. If there are no meaningful findings, say that explicitly and mention any residual testing gaps.

## Decision Points

- Missing test or weak test: prefer adding a new test only when the existing one cannot be strengthened cleanly.
- Parameterized or split apart: split when cases need different setup, different assertions, or clearer failure reporting.
- Inline fix or helper cleanup: prefer inline fixes unless repetition is actively hiding the behavior under test.
- Style issue or real risk: report style only when it affects readability enough to harm maintenance or diagnosis.
- Metadata or noise: keep tags, traits, or attachments only when they help execution, selection, traceability, or debugging.

## Anti-Patterns

- Never praise a test suite just because it is large; coverage volume is not the same as protection quality.
- Never call out naming or formatting as a primary finding when the real problem is missing behavior coverage.
- Never recommend parameterization when it will blur distinct failure modes.
- Never accept sleeps, retries, or timing margins as the default fix for async test instability.
- Never preserve weak assertions that would still pass after the behavior regresses.

## Quality Bar

- Findings should focus on bugs, regressions, flakiness, and meaningful coverage gaps.
- Each finding should explain why the current test is insufficient.
- Suggested fixes should be behavior-oriented and minimal.
- Review comments should match local repository style and conventions unless those conventions are the problem.
- If no serious findings exist, say so plainly instead of inventing low-value nits.

## Completion Checks

- The review distinguishes major risks from cosmetic issues.
- Weak assertions, missing edge cases, and flaky async patterns are covered where relevant.
- Any recommended code change is small enough to justify itself.
- The output makes clear whether the suite meaningfully protects the target behavior.

## Output Expectations

When using this skill, produce:

1. Findings first, ordered by severity, with concrete risk.
2. Open questions or assumptions if the intended behavior is unclear.
3. Optional code changes or rewrite suggestions only where they materially improve the tests.
4. A brief summary or residual risk note after the findings.

## Example Prompts

- Review this Swift Testing suite for weak assertions and missing edge cases.
- Audit these parameterized Swift tests and tell me whether they should be split apart.
- Find the flakiest async patterns in this Swift Testing file and tighten them.
- Review this regression coverage and tell me what failures could still slip through.

## References

- [Swift Testing review checklist](./references/swift-testing-review-checklist.md)
- [Swift Testing review examples](./references/swift-testing-review-examples.md)
- Apple Swift Testing overview: https://developer.apple.com/documentation/Testing

