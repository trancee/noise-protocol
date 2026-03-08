# JUnit Reference Map

Use this file as the first routing layer before opening external JUnit docs.

## Request Routing

### Write or Update Tests

Primary topics:

- Writing Tests in JUnit Jupiter
- Assertions
- Assumptions
- Parameterized tests
- Repeated tests
- Dynamic tests
- Test interfaces and lifecycle callbacks

Use this path when the user wants new tests, wants existing tests modernized, or needs a test pattern translated into current Jupiter APIs.

### Migrate from JUnit 4

Primary topics:

- Migrating from JUnit 4 to JUnit Jupiter
- Vintage engine guidance only when transitional execution is required

Migration rules:

- Prefer direct migration to Jupiter annotations and assertions.
- Keep Vintage only as a temporary bridge for mixed suites.
- Replace custom runners with Jupiter extensions or suite support where possible.

### Run or Discover Tests

Primary topics:

- Build support
- IDE support
- Console Launcher
- JUnit Platform Suite Engine

Troubleshooting order:

1. Verify Java runtime compatibility.
2. Verify dependencies and test engine presence.
3. Verify build-tool configuration.
4. Only then change test code.

### Extension or Platform Work

Primary topics:

- Extension Model for JUnit Jupiter
- Launcher API
- Other platform verification APIs when explicitly requested

Use this path only when fixtures, reusable callbacks, execution interception, or launcher integration are the actual problem.

## Version and Environment Rules

- JUnit 6 requires Java 17 or newer at runtime.
- New test authoring should default to JUnit Jupiter.
- JUnit Vintage is deprecated and should not be the target for new tests.
- Match Maven guidance to Maven builds and Gradle guidance to Gradle builds.

## Output Rules

When producing code:

- Write runnable Jupiter tests, not placeholders.
- Preserve repository naming and package conventions.
- Prefer parameterized tests over repetitive duplication.
- State any environment assumption that affects correctness.

When producing guidance:

- Explain why a migration or setup change is needed.
- Keep advice tied to the detected project context.
- Avoid framework-agnostic testing advice unless the user asked for comparison.

## External Documentation Map

- Overview: https://docs.junit.org/6.0.3/overview.html
- Writing tests: https://docs.junit.org/6.0.3/writing-tests/intro.html
- Migration: https://docs.junit.org/6.0.3/migrating-from-junit4.html
- Running tests: https://docs.junit.org/6.0.3/running-tests/intro.html
- Extensions: https://docs.junit.org/6.0.3/extensions/overview.html
- Launcher API: https://docs.junit.org/6.0.3/advanced-topics/launcher-api.html
