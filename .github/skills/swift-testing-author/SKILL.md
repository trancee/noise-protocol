---
name: swift-testing-author
description: 'Author new tests with Apple Swift Testing for Swift packages and Xcode projects. Use when asked to write Swift tests, scaffold test suites, add parameterized tests, apply traits or tags, structure coverage, or turn requirements and bugs into Swift Testing code using @Test, @Suite, #expect, #require, async tests, and attachments.'
argument-hint: 'What behavior, bug, or API should the new Swift Testing coverage verify?'
user-invocable: true
---

# Swift Testing Author

Use this skill to add or refine new tests written with Apple Swift Testing. Prefer it when the user wants new test coverage in a Swift 6 and Xcode 16+ codebase that already uses Swift Testing or is explicitly adopting it.

Load [Swift Testing reference notes](./references/swift-testing-reference.md) when you need framework-specific reminders about test shape, assertions, parameterization, concurrency, or metadata.
Load [Swift Testing authoring patterns](./references/swift-testing-patterns.md) when you need concrete code shapes for single-behavior tests, parameterized tests, async coverage, or regression scaffolds.

## When to Use This Skill

- The user asks to write a new test or test suite in Swift.
- The task needs parameterized tests across multiple inputs.
- The code under test uses async or throwing APIs.
- The user wants better test organization with suites, tags, or traits.
- A bug report or requirement needs to become a regression test.

## When Not to Use This Skill

- The user wants to migrate existing XCTest code; use a separate migration workflow instead.
- The user wants a review or audit of existing tests without necessarily authoring new ones.
- The repository has not adopted Swift Testing in the target area and the user has not asked to introduce it.
- The task is about generic build failures, test infrastructure, or CI setup rather than writing test coverage.

## Prerequisites

- Confirm whether the project uses Swift Package Manager tests, Xcode test targets, or both.
- Inspect nearby tests and follow the repository's naming, file layout, and fixture style.
- Identify the subject under test, the behavior to verify, and any edge cases that matter.
- If the repository still uses XCTest as the active convention, ask before introducing Swift Testing into that area.
- Keep verification guidance framework-focused unless repo-specific test commands are known and verified.

## Before Writing

Ask these questions before choosing a test shape:

- What observable behavior matters to the user or caller?
- What input or state change would prove that behavior works or regresses?
- Which edge case is easy to miss if the implementation changes later?
- What is the narrowest test target that can validate this without unrelated noise?

## Workflow

### 1. Confirm the Testing Context

1. Find the target package or test bundle that should hold the new tests.
2. Check whether Swift Testing is already present and preferred in that part of the codebase.
3. Identify how tests are currently run so verification can stay local and fast.

### 2. Translate the Request into Behaviors

1. Reduce the request to concrete behaviors, not implementation details.
2. Separate happy-path, edge-case, error-path, and regression scenarios.
3. Decide what inputs, outputs, and side effects each scenario must verify.

### 3. Choose the Right Test Shape

- Use a single `@Test` for one isolated behavior.
- Use a `@Suite` when several related behaviors belong together or need a shared conceptual grouping.
- Use parameterized tests when the same assertion should hold across many values and separate hand-written tests would only duplicate structure.
- Use tags when the suite needs stable categories such as feature area, regression coverage, or slow tests.
- Add traits only when they materially change execution or test metadata.

### 4. Implement the Test

1. Name tests by behavior and expected outcome.
2. Prefer direct setup inside the test unless helper extraction clearly improves readability.
3. Use `#expect(...)` for ordinary assertions.
4. Use `#require(...)` when the rest of the test cannot produce meaningful diagnostics if a precondition is missing.
5. Mark tests `async`, `throws`, or both only when the code under test requires it.
6. Add attachments or bug references when they improve diagnosis or traceability.
7. If the right structure is unclear, consult [Swift Testing authoring patterns](./references/swift-testing-patterns.md) and adapt the closest example to local repository style.

### 5. Verify and Tighten

1. Run the narrowest relevant test command first.
2. Fix compilation issues, incorrect imports, concurrency mismatches, and flaky assumptions.
3. Check that failures produce useful messages and point to the real broken behavior.
4. Remove duplicated setup if parameterization or a small helper would make the tests clearer.

## Decision Points

- Separate tests or one parameterized test: parameterize only when the assertion logic is the same and the case list improves coverage more than it hurts readability.
- `@Suite` or flat tests: prefer a suite when it clarifies ownership and behavior grouping, not just to add structure for its own sake.
- `#expect` or `#require`: use `#require` only for gating conditions that would make later assertions noisy or misleading.
- Traits and tags or none: add them when they affect test selection, execution, or traceability; skip them when they only add ceremony.
- Inline setup or helper builders: keep setup inline until repeated fixture construction starts hiding the behavior under test.

## Anti-Patterns

- Never introduce Swift Testing into an XCTest-heavy area without checking whether that part of the repository is intentionally staying on XCTest.
- Never parameterize cases that need different setup or different assertions just to reduce line count.
- Never use sleeps or timing guesses to make async tests pass when you can await the real behavior boundary.
- Never add tags, traits, attachments, or bug references as decoration; each one should help selection, execution, diagnosis, or traceability.
- Never hide the core behavior behind large shared helpers when inline setup would make the test easier to understand.

## Quality Bar

- Each test should verify one clear behavior.
- Tests should be deterministic and isolated from shared mutable state.
- Names should read like observable behavior, not internal implementation.
- Parameterization should reduce duplication without obscuring failing cases.
- Async tests should await real behavior boundaries instead of relying on timing guesses.
- The new tests should match local repository style unless the user explicitly asks to establish a new pattern.

## Completion Checks

- The test compiles in the intended target.
- The assertions would fail if the behavior regressed.
- The test file location and naming match nearby conventions.
- The added coverage addresses the requested behavior, edge case, or bug.
- Any tags, traits, or attachments included have a concrete purpose.

## Output Expectations

When using this skill, produce:

1. The new or updated Swift test code.
2. A brief note on why the chosen structure fits the behavior.
3. The verification command or the reason verification could not be run.

## Example Prompts

- Write Swift Testing coverage for a JSON decoder that should reject missing required fields.
- Add a parameterized Swift Testing test for this slug formatter across valid and invalid inputs.
- Create a regression test in Swift Testing for this async race condition.
- Scaffold a Swift Testing suite for these currency conversion rules.

## References

- [Swift Testing reference notes](./references/swift-testing-reference.md)
- [Swift Testing authoring patterns](./references/swift-testing-patterns.md)
- Apple Swift Testing overview: https://developer.apple.com/documentation/Testing
- Meet Swift Testing: https://developer.apple.com/videos/play/wwdc2024/10179
- Go further with Swift Testing: https://developer.apple.com/videos/play/wwdc2024/10195

