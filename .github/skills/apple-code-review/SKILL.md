---
name: apple-code-review
description: 'Review Swift, SwiftUI, and Apple-platform code for correctness risks before style issues. Use when asked to review a patch, inspect a Swift or SwiftUI implementation, look for behavioral regressions, check availability handling, verify actor isolation or main-thread assumptions, or assess UIKit/AppKit/SwiftUI integration risks.'
---

# Apple Code Review

Use this skill when the task is to review Apple-platform code and identify real defects, regressions, and risk areas rather than provide a style pass.

## When to Use This Skill

- The user asks for a review of Swift, SwiftUI, UIKit, AppKit, Foundation, or mixed-framework code.
- The task is to inspect a patch for regressions or hidden correctness issues.
- The change touches concurrency, availability, lifecycle, persistence, or UI state flow.
- The code crosses framework boundaries such as SwiftUI with UIKit or AppKit.

## Primary Goal

Find the highest-signal issues first:

- Behavioral bugs
- Regressions against existing semantics
- Incorrect availability or platform assumptions
- Actor isolation and thread-safety violations
- Lifecycle and ownership mistakes
- Integration mistakes across Apple frameworks

Do not spend the review budget on formatting or subjective style unless those issues hide a real defect.

## Review Workflow

### 1. Identify Review Surface

Classify the changed code before judging it:

- Swift language or standard library
- SwiftUI state, navigation, layout, or view lifecycle
- UIKit or AppKit lifecycle and presentation
- Foundation or persistence behavior
- Concurrency and isolation
- Interoperability or framework bridging

Use that classification to drive what risks deserve attention.

### 2. Look for Behavior Changes First

Check whether the patch changes runtime behavior in ways the author may not intend:

- Different state ownership or mutation timing
- Changed threading behavior or queue assumptions
- Different navigation, presentation, or dismissal semantics
- Changes to persistence timing, model identity, or data loss risk
- Altered error propagation, cancellation, or task lifetime

If a change appears intentional, verify that the implementation actually achieves it.

### 3. Check Apple-Specific Risk Areas

Inspect for these classes of issues:

- Availability: APIs used without correct platform or OS gating
- Concurrency: missing actor isolation, unsafe Sendable assumptions, detached tasks, main-thread violations
- SwiftUI data flow: duplicated sources of truth, unstable identity, stale bindings, observation mismatches
- UIKit or AppKit lifecycle: invalid presentation timing, missing ownership, view-controller containment mistakes
- Integration: incorrect bridging between SwiftUI and UIKit or AppKit, coordinator misuse, update cycle bugs
- Persistence and model updates: writes in the wrong lifecycle phase, missing durability assumptions, inconsistent model mutation

### 4. Demand Evidence for Non-Obvious Claims

When the safety of a change depends on framework behavior:

- Prefer documented Apple behavior over intuition
- Treat undocumented implementation details as unstable
- Call out version sensitivity if behavior changed across OS or Swift releases

### 5. Rank Findings by Severity

Prioritize issues in this order:

1. Crashes, data loss, deadlocks, and security-sensitive flaws
2. Concurrency violations and correctness regressions
3. Lifecycle, state-flow, and integration bugs
4. Performance problems with likely user impact
5. Maintainability concerns only when they materially increase bug risk

### 6. Write Findings Precisely

Each finding should state:

- What is wrong
- Why it is risky or incorrect
- Under what condition it fails
- The file and line reference when available
- The narrowest credible fix direction

## Decision Rules

- If there are no concrete defects, say so explicitly instead of inventing style comments.
- If a concern depends on an assumption, state the assumption.
- If the code is SwiftUI, treat data ownership and identity as review priorities before view composition details.
- If the code uses async or actors, verify isolation and cancellation semantics before judging surface logic.
- If the code mixes frameworks, inspect lifecycle boundaries before smaller API usage details.
- If a performance issue is speculative and unsupported, do not elevate it above confirmed correctness bugs.

## Output Format

Review responses should:

- Lead with findings, ordered by severity
- Keep summaries brief and secondary
- Include open questions only when they materially affect correctness
- Mention testing gaps or residual risk if no findings are discovered

## Quality Checks

Before finalizing, verify:

- Findings describe actual defects or credible regression risks
- Severity matches user impact and likelihood
- Claims about Apple framework behavior are documented or explicitly qualified
- Suggested fixes are narrow and actionable
- The response stays focused on correctness over style

## Example Prompts

- Review this SwiftUI patch for state, navigation, and observation regressions.
- Review this UIKit to SwiftUI integration for lifecycle and update-cycle bugs.
- Inspect this Swift concurrency change for actor isolation and cancellation issues.
- Review this Foundation persistence refactor for data-loss or ordering risks.

## References

- Apple Developer Swift documentation: https://developer.apple.com/documentation/swift
- Apple Developer SwiftUI documentation: https://developer.apple.com/documentation/swiftui