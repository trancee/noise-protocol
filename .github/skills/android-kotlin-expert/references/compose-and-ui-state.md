# Compose And UI State

## Default Guidance

- Keep composables focused on rendering and user interaction.
- Hoist state when multiple composables need to coordinate around the same source of truth.
- Model screen state as an immutable UI state object rather than many unrelated mutable fields.
- Treat one-off effects such as navigation, snackbars, and toasts separately from long-lived UI state.

## Compose Heuristics

- Prefer stateless composables where practical and pass state plus callbacks explicitly.
- Use `collectAsStateWithLifecycle` for `Flow`-backed UI state in Android-aware Compose screens.
- Avoid launching work directly from composables unless it is tied to a clear side-effect API such as `LaunchedEffect`.
- Keep expensive work out of recomposition paths.

## Common Problems

- Business logic embedded inside composables.
- Mutable state split across too many places.
- Navigation events modeled as persistent state instead of one-time effects.
- Re-triggered side effects caused by unstable keys or recomposition misunderstandings.

## Review Questions

- Who owns this state?
- What survives configuration change?
- Is this value persistent screen state or a transient effect?
- Will this coroutine restart unexpectedly on recomposition?
