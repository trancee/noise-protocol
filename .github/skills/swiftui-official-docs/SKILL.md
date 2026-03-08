---
name: swiftui-official-docs
description: 'Research and apply SwiftUI guidance using Apple documentation first. Use when asked to implement or refactor SwiftUI views, fix state-management or navigation issues, choose between Observation and older patterns, verify modifiers or container behavior, integrate SwiftUI with UIKit or AppKit, or ground UI code changes in official docs.'
---

# SwiftUI Official Docs

Use this skill when a SwiftUI task should be explained, implemented, or refactored from Apple documentation instead of habit or community convention.

## When to Use This Skill

- The user asks how a SwiftUI API, modifier, or container behaves.
- The task involves state, observation, environment, navigation, scenes, or layout.
- A view or app structure needs refactoring and the recommended Apple pattern matters.
- The task mixes SwiftUI with UIKit, AppKit, WatchKit, or another Apple framework.
- The user wants code changes backed by official SwiftUI guidance.

## Scope

This skill is optimized for:

- App and scene structure
- Navigation and modal presentation
- Model data, environment values, preferences, and persistent storage
- Observation and state-driven UI updates
- View composition, modifiers, controls, animations, and layout
- SwiftUI integration with UIKit, AppKit, WatchKit, and technology-specific views
- Previews and tool-supported validation

This skill is not the primary workflow for:

- Pure Swift language questions with no SwiftUI impact
- Visual design choices that do not depend on framework behavior
- Reverse-engineering undocumented rendering or lifecycle behavior

## Workflow

### 1. Classify the UI Problem

Place the request into one or more buckets:

- App structure: App, Scene, WindowGroup, document apps, multiwindow concerns
- Navigation: NavigationStack, destinations, split views, modal flows
- Data flow: Observation, environment, bindings, preferences, persistence
- View composition: modifiers, controls, lists, tables, forms, custom views
- Layout: stacks, grids, custom layout, scroll views, spacing, alignment
- Interaction: gestures, focus, search, system events, drag and drop
- Integration: UIKit/AppKit bridging, representables, mixed-framework adoption
- Tooling: previews, performance analysis, library customization

If multiple buckets apply, solve state and data-flow correctness first, then navigation, then composition and layout.

### 2. Prefer Official Sources in This Order

1. Apple SwiftUI documentation for the exact API or topic area
2. Apple sample or conceptual articles linked from the SwiftUI docs when the task is architectural
3. Swift language documentation only when the SwiftUI behavior depends on a language rule

Do not generalize from older community patterns when the docs provide a newer recommended mechanism.

### 3. Extract Only the Relevant Guidance

Pull the smallest set of material needed to answer or change the code:

- Exact symbol or topic page
- Availability and platform limitations
- Lifecycle, data ownership, and update semantics
- Integration constraints for UIKit, AppKit, or other frameworks
- Example usage only if it clarifies the intended pattern

### 4. Convert Guidance Into Code Changes

Apply the docs directly to the codebase:

- Replace outdated patterns when Apple documents a current alternative
- Align ownership of state with the documented data-flow model
- Use the documented navigation or presentation mechanism instead of ad hoc routing logic
- Prefer smaller view and model changes over broad rewrites
- Preserve existing behavior unless the task explicitly requests a UX or architecture change

### 5. Validate the Change

Before finalizing, check that the proposed code:

- Uses documented API names and availability correctly
- Matches SwiftUI's documented data-flow and lifecycle expectations
- Does not mix conflicting state-management patterns without justification
- Keeps cross-framework integration within documented boundaries
- Remains testable or previewable where applicable

### 6. Check for Ambiguity

Ask a follow-up only if one of these blocks a reliable answer or refactor:

- Platform target matters and is unknown
- The code relies on deprecated or version-sensitive APIs
- The request mixes framework behavior with product-design preference
- The intended ownership of state or navigation source of truth is unclear

## Decision Rules

- If the issue is stale or duplicated UI state, resolve ownership and observation first.
- If the issue is navigation, prefer the documented navigation API for the current platform target rather than custom routing unless the app constraints require it.
- If the issue is layout, prefer documented layout containers and modifiers before custom layout code.
- If UIKit or AppKit is involved, verify the integration boundary in Apple docs before refactoring.
- If the docs present a newer pattern than the existing code, explain the migration and refactor toward it.
- If the docs do not guarantee a behavior, do not treat it as stable framework contract.

## Output Expectations

Produce results that:

- State the relevant SwiftUI behavior clearly
- Tie recommendations to official documentation, not convention alone
- Call out platform or version constraints when they matter
- End with a concrete implementation change, refactor plan, or code patch when requested
- Separate framework rules from subjective UI preferences

## Quality Checks

Before finalizing, verify:

- The recommendation is grounded in Apple SwiftUI documentation
- State ownership and data flow are internally consistent
- Navigation and presentation APIs match the target platform and availability
- Example code is minimal, idiomatic, and consistent with current documented patterns
- Any remaining uncertainty is explicit

## Example Prompts

- Use official SwiftUI docs to fix the state flow in this view hierarchy.
- Compare Observation and ObservableObject from Apple docs, then refactor this feature.
- Verify whether this NavigationStack pattern is correct for current SwiftUI and update it.
- Use Apple docs to restructure this modal presentation flow.
- Check the documented way to embed UIKit in SwiftUI and fix this wrapper.

## References

- Apple Developer SwiftUI documentation: https://developer.apple.com/documentation/swiftui
- SwiftUI Pathway: https://developer.apple.com/swiftui/get-started/