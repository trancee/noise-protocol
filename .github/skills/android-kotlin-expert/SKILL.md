---
name: android-kotlin-expert
description: 'Build and review Android code written in Kotlin. Use when working with Jetpack Compose, ViewModel, StateFlow, coroutines, lifecycle-aware UI state, app architecture, repository patterns, navigation, or Android-specific Kotlin tradeoffs.'
argument-hint: 'What Android Kotlin problem, code sample, or architecture question do you need help with?'
---

# Android Kotlin Expert

Use this skill for Android-specific Kotlin work where platform concerns matter: UI state, lifecycle, ViewModel ownership, Flow collection, app architecture, navigation, persistence, and testing.

## When to Use

- Review Android Kotlin code for architecture, lifecycle, or state-management issues.
- Design or refine Jetpack Compose screens and state holders.
- Explain ViewModel, `StateFlow`, `SharedFlow`, and coroutine usage in Android apps.
- Translate general Kotlin patterns into Android-safe implementations.
- Generate Android code examples that need lifecycle awareness or framework integration.
- Audit Android tests for ViewModel, Flow, repository, or Compose behavior.

## Scope Boundaries

- Use this skill when Android APIs, Jetpack libraries, or mobile app structure materially affect the answer.
- Prefer the general Kotlin skill for pure language questions that are not Android-specific.
- Call out build-system, manifest, or device-specific concerns separately when they are not central to the code question.

## Procedure

1. Identify the Android layer involved.
   Classify the task as UI, state holder, domain, data, navigation, persistence, background work, or testing.
2. Establish ownership and lifecycle.
   Determine which component owns state, launches coroutines, and survives configuration changes.
3. Prefer unidirectional state flow.
   Model UI with immutable state, explicit events, and observable state streams.
4. Keep Android code lifecycle-aware.
   Avoid work that outlives the owning scope unless that behavior is intentional.
5. Separate platform concerns from domain logic.
   Push business rules out of composables, activities, and fragments when practical.
6. Choose Android-friendly APIs.
   Favor `ViewModel`, `StateFlow`, `collectAsStateWithLifecycle`, repository boundaries, and testable abstractions.
7. Close with operational risks.
   Call out recomposition issues, leaked work, stale state, navigation coupling, or test fragility.

## Decision Points

- If the user is building UI, explain state ownership before discussing rendering details.
- If Compose is involved, distinguish stable state, transient events, and side effects.
- If coroutines are involved, explain scope ownership, cancellation, and dispatcher choice in Android terms.
- If persistence or networking appears, keep IO behind repository or data-source boundaries.
- If the code mixes Android framework logic with business rules, suggest a cleaner seam rather than only patching symptoms.
- If testing is involved, prefer deterministic unit tests for state holders and smaller targeted UI tests.

## Quality Checks

- The answer respects Android lifecycle boundaries.
- UI state is observable, immutable at the boundary, and owned by the right component.
- Coroutines are launched from an appropriate scope.
- The guidance avoids unnecessary framework coupling.
- Testing advice matches the layer being discussed.

## Reference Material

- [Compose and UI state](./references/compose-and-ui-state.md)
- [Architecture and data flow](./references/architecture-and-data-flow.md)
