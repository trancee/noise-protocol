# Advanced Kotlin Topics

This reference covers the topics that commonly extend beyond basic syntax but still belong in a Kotlin-focused skill.

## Idiomatic Modeling

- Prefer `data class` for plain immutable value objects.
- Use `sealed class` or `sealed interface` when modeling a closed set of states.
- Prefer `enum class` only for a small fixed set of constants without richer subtype behavior.
- Use extension functions when they improve discoverability and readability, not just to move code around.

## Collections And Standard Library Style

- Prefer collection operators such as `map`, `filter`, `associateBy`, `groupBy`, `fold`, and `firstOrNull` when they are clearer than manual loops.
- Avoid chaining so many operators that a simple loop would be easier to read.
- Know the difference between eager collections and lazy `Sequence` pipelines.

## Null Safety And Error Handling

- Prefer explicit nullable modeling over sentinel values.
- Use safe calls, Elvis operators, and early returns to keep control flow linear.
- Use `require`, `check`, and `error` for contract and invariant failures when appropriate.
- Avoid `!!` unless there is a clear, documented invariant.

## Coroutines

- Explain coroutine scope ownership before implementation details.
- Prefer structured concurrency and cancellation-aware code.
- Distinguish clearly between `suspend` functions, `CoroutineScope.launch`, and `async`.
- Avoid `GlobalScope` unless the user explicitly asks about fire-and-forget tradeoffs.

## Java Interop

- Preserve Java-facing APIs when needed, even if pure Kotlin would look different.
- Be aware of platform types from Java and treat them carefully around nullability.
- Use annotations or overload strategies only when they materially improve the interop story.

## Testing

- Keep unit test examples small and deterministic.
- Prefer readable assertions and minimal fixture setup.
- Separate coroutine testing concerns from regular synchronous tests.

## Common Review Heuristics

- Replace mutable state with immutable flows where practical.
- Collapse verbose getter-style code into Kotlin properties when appropriate.
- Prefer expression-oriented Kotlin over statement-heavy Java style.
- Watch for overuse of scope functions; choose `let`, `run`, `apply`, `also`, and `with` only when each one makes the code clearer.
