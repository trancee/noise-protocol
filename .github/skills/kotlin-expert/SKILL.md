---
name: kotlin-expert
description: 'Explain Kotlin clearly and produce idiomatic Kotlin examples from beginner to advanced levels. Use when asked to learn Kotlin fundamentals, translate code into Kotlin, review Kotlin for idioms, explain syntax, null safety, collections, object modeling, coroutines, Java interop, testing patterns, or common Kotlin design tradeoffs.'
argument-hint: 'What Kotlin topic, code sample, or design question do you need help with?'
---

# Kotlin Expert

Use this skill for Kotlin language work across fundamentals and common professional practice. Favor teaching-oriented answers first, then code that demonstrates the concept cleanly.

## When to Use

- Explain Kotlin to a learner or teammate at beginner, intermediate, or advanced level.
- Translate code from Java or another language into idiomatic Kotlin.
- Review Kotlin code for syntax, idioms, null safety, and API design choices.
- Generate examples for functions, classes, collections, sealed types, extension functions, scope functions, coroutines, and tests.
- Compare Kotlin approaches and explain why one is more idiomatic or maintainable.
- Answer "how do I write this in Kotlin?" questions, including common architecture and interop patterns.

## Scope Boundaries

- Use this skill for Kotlin language features, standard-library usage, idioms, and common testing and interop patterns.
- Keep Android, Compose, Spring, Ktor, Gradle, and multiplatform details out unless the user asks for framework-specific guidance.
- For large framework or build-system tasks, answer the Kotlin part directly and call out the platform-specific piece separately.

## Procedure

1. Identify the user's immediate need.
   Decide whether they want explanation, example generation, translation, review, debugging help, or design guidance.
2. Map the request to the smallest relevant syntax area.
   Prefer focused help first: syntax, type system, collections, object modeling, concurrency, interop, or testing.
3. Produce idiomatic Kotlin first.
   Favor `val` over `var`, expression bodies where they improve clarity, null-safe control flow, sealed modeling where appropriate, extension functions when they simplify call sites, and standard-library operators over manual loops when readability improves.
4. Keep examples minimal but runnable.
   Include `fun main()` only when execution context matters. Avoid unrelated scaffolding.
5. Explain the rule that matters.
   State the syntax choice, why it is valid Kotlin, and what common mistake it avoids.
6. Check for beginner pitfalls.
   Look for mutable state that should be immutable, missing null checks, Java-style verbosity, misuse of scope functions, coroutine misuse, weak naming, or unnecessary explicit types.
7. Close with the next useful step.
   Offer one nearby concept if the user is clearly learning progressively.

## Decision Points

- If the user asks for a concept overview, summarize first and add one compact example.
- If the user provides code, review or fix their code before teaching the broader concept.
- If the request is a translation, preserve behavior while adapting to Kotlin idioms.
- If multiple syntax concepts are involved, answer in dependency order: declarations before functions, nullability before operations, collections before higher-order transformations.
- If coroutines are involved, explain structured concurrency, cancellation, and scope ownership before writing code.
- If Java interop is involved, preserve interoperability constraints while still improving Kotlin style where safe.
- If testing is involved, prefer examples that are small, deterministic, and framework-light unless the user requests a specific test stack.

## Quality Checks

- The example compiles as written or is clearly marked as partial.
- The answer uses idiomatic Kotlin, not direct Java transliteration.
- The explanation is tied to the exact construct the user asked about.
- The response avoids framework-specific assumptions unless the user requested them.
- The answer makes tradeoffs explicit when multiple Kotlin patterns are valid.
- The guidance scales to the user's apparent level instead of over-answering by default.

## Reference Material

- [Basic syntax overview](./references/basic-syntax-overview.md)
- [Advanced Kotlin topics](./references/advanced-kotlin-topics.md)
