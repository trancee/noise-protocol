---
name: swift6-concurrency-migration
description: 'Migrate Swift code toward Swift 6 strict concurrency safely and incrementally. Use when asked to fix Sendable errors, actor-isolation violations, main-actor issues, async migration problems, strict concurrency warnings, or to plan or implement staged adoption of Swift 6 language mode.'
---

# Swift 6 Concurrency Migration

Use this skill when the task is to prepare a codebase for Swift 6 or fix concurrency diagnostics in a way that aligns with Apple and Swift.org guidance.

## When to Use This Skill

- The user wants to adopt Swift 6 language mode or stricter concurrency checking.
- The codebase has Sendable, actor-isolation, MainActor, or async diagnostics.
- A patch introduces concurrency warnings that need a correct fix rather than a suppression.
- The task is to migrate code incrementally across modules or targets.

## Scope

This skill is optimized for:

- Strict concurrency adoption strategy
- Actor-isolation fixes
- Sendable conformance analysis
- MainActor and UI-thread correctness
- Async API migration and bridging
- Incremental project or module migration

This skill is not the primary workflow for:

- General SwiftUI architecture unrelated to concurrency
- Performance tuning that is not driven by concurrency correctness
- Disabling diagnostics just to make builds pass

## Workflow

### 1. Classify the Migration Problem

Identify which class of issue is present:

- Build setting and migration staging
- Actor isolation and crossing actor boundaries
- MainActor correctness for UI-facing code
- Sendable requirements on values, closures, and generic types
- Async migration from callbacks or older patterns
- Shared mutable state and data-race risk

If the code spans multiple modules, prefer a staged approach instead of a workspace-wide rewrite.

### 2. Prefer Official Sources in This Order

1. Apple guidance for adopting strict concurrency in Swift 6 apps
2. Swift.org migration guidance for Swift 6 interoperability and staged adoption
3. Swift language documentation for concurrency semantics

Use Apple guidance to decide migration order and build-setting strategy, then use language docs to justify code-level fixes.

### 3. Stabilize the Migration Surface

Before large edits:

- Determine whether the task is in Swift 5 mode with stricter checking or full Swift 6 mode
- Prefer increasing strict concurrency checking deliberately rather than assuming the whole project should jump to Swift 6 immediately
- If the app is modular, migrate one module at a time where practical

### 4. Fix Root Causes, Not Diagnostics Symptoms

When addressing compiler warnings or errors:

- Remove shared mutable state or isolate it appropriately
- Add actor isolation only where it reflects real ownership and execution constraints
- Add Sendable conformance only when the type actually satisfies the contract
- Prefer redesigning unsafe access patterns over adding unchecked escape hatches
- Use MainActor for UI-bound code when that matches documented threading expectations

### 5. Keep Changes Incremental

Prefer the smallest safe change that improves correctness:

- Fix one ownership or isolation boundary at a time
- Avoid broad annotation sweeps without understanding the access patterns
- Separate build-setting changes from code refactors when possible
- Preserve behavior unless the migration requires a deliberate concurrency model change

### 6. Validate the Migration

Before finalizing, check that:

- The fix eliminates a real data-race risk or satisfies a real isolation contract
- Sendable annotations are justified, not decorative
- MainActor usage matches UI or main-thread requirements
- The code remains compatible with the current target Swift mode and platform constraints
- Remaining diagnostics are called out if full cleanup is not feasible

## Decision Rules

- If a warning indicates shared mutable state, address the state ownership first.
- If a UI type or API is involved, verify whether MainActor isolation is the correct boundary.
- If a type cannot safely satisfy Sendable, do not force conformance just to silence diagnostics.
- If migration scope is large, propose staged adoption instead of one-shot conversion.
- If interoperation with not-yet-migrated code is necessary, contain the boundary and document the compromise.
- If the only apparent fix is an unchecked annotation, explain the tradeoff and prefer a safer design if feasible.

## Output Expectations

Produce results that:

- Explain the relevant concurrency rule briefly and accurately
- Distinguish migration strategy from code-level fixes
- Apply the smallest correct change that improves concurrency safety
- Mention Swift mode, strict checking level, or module-staging assumptions when they matter
- End with a concrete patch, migration step, or follow-up plan

## Quality Checks

Before finalizing, verify:

- The change is aligned with Apple or Swift.org migration guidance
- Actor isolation and Sendable reasoning are coherent
- Main-thread or MainActor assumptions are explicit
- The fix does not merely suppress the diagnostic without addressing the underlying race risk
- Any remaining migration debt is named clearly

## Example Prompts

- Fix these Swift 6 Sendable errors using the smallest correct migration.
- Plan an incremental migration to strict concurrency for this modular app.
- Refactor this view model to satisfy MainActor and actor-isolation requirements.
- Use official guidance to decide whether this type should conform to Sendable.

## References

- Apple Developer: Adopting strict concurrency in Swift 6 apps: https://developer.apple.com/documentation/swift/adoptingswift6
- Swift.org migration guidance: https://swift.org/migration/
- The Swift Programming Language, Concurrency: https://docs.swift.org/swift-book/LanguageGuide/Concurrency.html