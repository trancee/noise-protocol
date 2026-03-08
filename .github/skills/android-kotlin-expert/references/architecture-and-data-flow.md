# Architecture And Data Flow

## Layering Guidance

- Keep UI, domain, and data concerns separated enough that each can be reasoned about independently.
- Use `ViewModel` as the boundary that prepares UI-facing state and handles UI events.
- Keep repositories responsible for coordinating data sources, not rendering concerns.
- Push long-running or blocking work off the main thread behind suspend functions or flows.

## Data Flow Heuristics

- Prefer a single observable UI state stream per screen when possible.
- Use explicit event handlers rather than letting the UI mutate deep objects directly.
- Model loading, success, and failure states intentionally.
- Avoid exposing mutable flows across layer boundaries; expose read-only types instead.

## Coroutines In Android

- Launch screen-related work from `viewModelScope` unless a narrower scope is more correct.
- Be explicit about dispatcher changes around blocking IO or CPU-heavy work.
- Prefer structured concurrency and cancellation-aware APIs.
- Avoid application-wide scopes unless the work truly matches application lifetime.

## Testing Guidance

- Unit test ViewModel state transitions without Android UI dependencies where possible.
- Test repositories around behavior and coordination, not implementation details.
- Keep Compose UI tests focused on rendering and interaction outcomes.

## Common Smells

- UI observing too many unrelated sources directly.
- ViewModels that contain persistence, networking, and formatting all at once.
- Repositories leaking Android framework classes.
- Mutable shared state crossing layer boundaries.
