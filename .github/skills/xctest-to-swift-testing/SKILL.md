---
name: xctest-to-swift-testing
description: 'Migrate XCTest tests to Apple Swift Testing in Swift packages and Xcode projects. Use when asked to convert XCTestCase classes, replace XCTAssert APIs, move setup-heavy tests into Swift Testing structure, preserve regression coverage during migration, or translate async and throwing XCTest patterns into @Test, @Suite, #expect, and #require.'
argument-hint: 'What XCTest file, suite, or pattern should be migrated to Swift Testing?'
user-invocable: true
---

# XCTest To Swift Testing

Use this skill to migrate existing XCTest code into Swift Testing while preserving behavior and keeping changes reviewable. Prefer it when the user wants conversion work rather than a fresh test design or a findings-first review.

Load [XCTest to Swift Testing mapping](./references/xctest-to-swift-testing-mapping.md) when you need concrete API translations and migration heuristics.
Load [XCTest to Swift Testing examples](./references/xctest-to-swift-testing-examples.md) when you need worked conversions for assertions, async tests, or setup-heavy test classes.

## When to Use This Skill

- The user asks to convert XCTest files or suites to Swift Testing.
- Existing tests rely on `XCTestCase`, `XCTAssert*`, or XCTest async patterns and should move to Swift Testing.
- A codebase is adopting Swift Testing incrementally and needs behavior-preserving migration.
- The user wants to replace setup-heavy test classes with clearer Swift Testing structure.

## When Not to Use This Skill

- The user wants a brand-new Swift Testing test written from scratch with no XCTest code to convert.
- The user wants a review of test quality without performing migration.
- The target area is intentionally staying on XCTest for compatibility or tooling reasons.
- The task is about CI, test discovery, or infrastructure rather than test code migration.

## Before Migrating

Ask these questions before converting anything:

- Is this area actually adopting Swift Testing now, or should the migration stop and ask first?
- Which behaviors are already protected, and which ones are fragile enough to regress during conversion?
- Does the existing XCTest code depend on class lifecycle hooks, shared mutable state, or order-sensitive setup?
- Can the migration stay behavior-preserving and incremental, or is there pressure to refactor test design at the same time?

## Workflow

### 1. Understand The Existing XCTest Surface

1. Identify the `XCTestCase` classes, helper methods, fixtures, and lifecycle hooks involved.
2. Determine which tests are straightforward assertions and which ones depend on setup/teardown or async expectations.
3. Separate migration work from unrelated cleanup so behavioral regressions stay visible.

### 2. Translate Structure First

1. Convert `XCTestCase` classes into free test functions or `@Suite` types only when grouping still adds clarity.
2. Remove inheritance-driven structure that no longer carries meaning in Swift Testing.
3. Keep related tests together, but do not recreate class ceremony just to mirror XCTest.

### 3. Translate Assertions And Preconditions

1. Replace `XCTAssert*` calls with `#expect(...)` where the behavior can be expressed directly.
2. Replace prerequisite-style assertions with `#require(...)` only when later checks would otherwise become misleading.
3. Keep the behavioral intent of each assertion intact instead of performing mechanical one-to-one rewrites that weaken failure messages.

### 4. Translate Async And Throwing Patterns

1. Replace XCTest expectation boilerplate with `async` and `await` when the API naturally supports it.
2. Convert throwing tests so the Swift Testing function signature reflects `throws` only when needed.
3. Remove timing guesses, wait helpers, and callback plumbing when a direct async boundary is available.

### 5. Tighten After Migration

1. Check whether leftover setup helpers should become local setup or small fixtures.
2. Keep tags, traits, or metadata minimal unless they materially help selection or diagnosis.
3. Run the narrowest relevant tests and confirm the migrated suite protects the same behavior as before.
4. If the migration exposes a real weakness in the original tests, call it out separately instead of quietly changing behavior.

## Decision Points

- Free tests or `@Suite`: use a suite when it still communicates ownership or behavior grouping after removing XCTest inheritance.
- Mechanical translation or structural cleanup: keep the first pass close to the original behavior unless the existing structure is actively hiding what the test verifies.
- `#expect` or `#require`: use `#require` only for gating values or states that would make later assertions meaningless.
- Keep helper or inline setup: inline setup when it improves readability after class fixtures disappear; keep a helper only when it still carries clear intent.
- Migrate now or stop and ask: stop when the repository has not clearly adopted Swift Testing in that target area.

## Anti-Patterns

- Never mix migration with broad refactoring unless the user explicitly wants both.
- Never preserve `XCTestCase`-style class ceremony in Swift Testing just because it existed before.
- Never perform a blind `XCTAssert` to `#expect` rewrite if it weakens the behavioral meaning of the assertion.
- Never keep expectation-and-wait boilerplate when direct async code expresses the behavior more clearly.
- Never change covered behavior during migration without calling it out explicitly.

## Quality Bar

- The migrated tests should protect the same behaviors as the original XCTest coverage.
- The resulting Swift Testing code should look native to Swift Testing, not like XCTest with renamed APIs.
- Async and throwing tests should become simpler, not more indirect.
- Any behavior changes discovered during migration should be surfaced clearly.
- The migration should stay small enough for review unless the user explicitly requests a larger cleanup.

## Completion Checks

- `XCTestCase` inheritance and obsolete XCTest ceremony are removed where migration is complete.
- Assertions express the intended behavior clearly in Swift Testing terms.
- Async or throwing paths use direct Swift concurrency where appropriate.
- The migrated tests remain aligned with local file layout and naming conventions.
- Verification was run, or the reason it could not be run is stated.

## Output Expectations

When using this skill, produce:

1. The migrated Swift Testing code.
2. A brief note describing the main XCTest-to-Swift-Testing translations used.
3. Any migration risks, open questions, or behavior changes discovered.
4. The verification command or the reason verification could not be run.

## Example Prompts

- Convert this XCTestCase file to Swift Testing without changing behavior.
- Migrate these XCTAssert-based tests to `#expect` and `#require`.
- Replace this XCTest async expectation pattern with Swift Testing.
- Port this setup-heavy XCTest suite to a cleaner Swift Testing structure.

## References

- [XCTest to Swift Testing mapping](./references/xctest-to-swift-testing-mapping.md)
- [XCTest to Swift Testing examples](./references/xctest-to-swift-testing-examples.md)
- Apple Swift Testing overview: https://developer.apple.com/documentation/Testing

