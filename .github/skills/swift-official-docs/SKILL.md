---
name: swift-official-docs
description: 'Research and apply Swift, SwiftUI, and Apple framework guidance using official documentation first. Use when asked to explain Swift language features, verify standard-library or SDK API behavior, check Swift 6 concurrency guidance, implement or refactor Swift code from Apple docs, compare framework approaches, or ground code changes in official Apple or Swift.org references.'
---

# Swift Official Docs

Use this skill when a Swift task should be answered or implemented from official documentation rather than memory or third-party examples.

## When to Use This Skill

- The user asks how a Swift language feature works.
- The task needs confirmation from Apple docs before changing code.
- You need official references for standard-library types, SwiftUI APIs, SDK behavior, concurrency, or interoperability.
- The user provides an Apple Developer or Swift.org documentation link.
- The task is to implement or refactor Swift code in a way that should match current documented guidance.

## Scope

This skill is optimized for:

- Swift language features and syntax
- Swift standard-library types and protocols
- SwiftUI APIs and state-management patterns
- Apple SDK frameworks when the task depends on documented API behavior
- Swift 6 migration and strict concurrency guidance
- Interoperability involving Objective-C, C, or C++

This skill is not the primary workflow for:

- Product or UX decisions that are independent of API behavior
- Build-system issues unless the docs directly determine the fix
- Reverse-engineering undocumented framework behavior

## Workflow

### 1. Classify the Request

Decide which bucket best fits the task:

- Language feature: optionals, generics, protocols, actors, closures, macros, error handling
- Standard library: String, Array, Dictionary, Result, AsyncSequence
- UI framework: SwiftUI views, state, navigation, observation, data flow
- SDK framework: Foundation, UIKit, AppKit, AVFoundation, Core Data, and similar APIs
- Concurrency and migration: strict concurrency, Sendable, actor isolation, async bridging
- Interoperability: Objective-C, C, C++, mixed-language targets

If the request crosses categories, split the problem and resolve the language or API-contract part before style or architecture preferences.

### 2. Prefer Official Sources in This Order

1. Apple Developer documentation for the exact Swift feature or SDK API
2. The Swift Programming Language book on Swift.org for language rules and narrative explanation
3. Apple migration or adoption guides for version-specific recommendations

Do not rely on memory when the behavior is version-sensitive, subtle, deprecated, or concurrency-related.

### 3. Extract the Smallest Useful Evidence

Pull only the documentation needed to answer or implement the task:

- The exact symbol, type, protocol, modifier, or feature page
- Availability and platform notes when relevant
- Migration guidance for Swift 6 or SDK transitions
- A short documented example only if it clarifies behavior or expected usage

### 4. Translate Docs Into Code Changes

Turn the documentation into concrete implementation guidance:

- Explain what the language rule or API guarantees
- Identify required constraints, lifecycle rules, threading rules, and availability limits
- Apply the guidance directly to the user's code
- Prefer the smallest correct code change over a broad rewrite
- If the docs imply a safer or more idiomatic API, refactor toward that API

### 5. Validate the Proposed Change

Before finalizing, check that the suggested code:

- Matches documented API names and calling patterns
- Respects platform and version availability
- Does not introduce concurrency violations against current guidance
- Preserves behavior unless the task explicitly requests a behavior change

### 6. Check for Ambiguity

Ask a follow-up only if one of these blocks a reliable answer or change:

- Swift version matters and is unknown
- Platform target matters and is unknown
- The task depends on undocumented behavior
- Multiple official sources conflict because of versioning or deprecation

## Decision Rules

- If the user asks a pure language question, start with Apple Swift docs and use Swift.org for deeper language explanation.
- If the user asks about a standard-library or framework symbol, prefer the exact symbol page over overview articles.
- If the task is SwiftUI, use the relevant Apple documentation for the state, observation, or navigation mechanism involved before recommending a pattern.
- If the task is implementation-oriented, convert the documentation into a concrete code change instead of stopping at explanation.
- If the answer depends on assumptions, state them explicitly.
- If the docs are silent on a behavior, do not present speculation as fact.

## Output Expectations

Produce results that:

- State the documented behavior clearly and directly
- Distinguish language rules from framework behavior
- Mention version or availability caveats when they matter
- Link the recommendation to the specific official docs consulted when useful
- End with a concrete recommendation, patch strategy, or code change when implementation is requested

## Quality Checks

Before finalizing, verify:

- The answer or change is grounded in an official source
- Swift 6 and concurrency statements are version-aware
- Framework recommendations are not being inferred from unrelated language rules
- Example code is idiomatic, minimal, and aligned with current docs
- Uncertainty is called out instead of guessed through

## Example Prompts

- Explain how Sendable affects this Swift 6 actor code using official docs and then fix the implementation.
- Use Apple docs to update this SwiftUI state flow to the recommended pattern.
- Find the docs for Array and tell me whether this mutation pattern is safe.
- Compare Apple guidance for Observation and ObservableObject, then refactor this view model.
- Use the official docs to explain how Objective-C completion handlers bridge to async and apply that to this API wrapper.

## References

- Apple Developer Swift documentation: https://developer.apple.com/documentation/swift
- The Swift Programming Language: https://docs.swift.org/swift-book/