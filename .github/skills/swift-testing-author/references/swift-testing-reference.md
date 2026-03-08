# Swift Testing Reference Notes

Use this reference when authoring tests with Apple Swift Testing and you need a compact reminder of the framework's main building blocks.

## Core Constructs

- `@Test`: Declare a test function.
- `@Suite`: Group related tests into a suite type.
- `#expect(...)`: Assert an expected condition or value.
- `#require(...)`: Stop the test early when a prerequisite is missing and later diagnostics would be misleading.

## Choosing Test Structure

- Prefer one `@Test` per observable behavior.
- Use `@Suite` when tests benefit from a named behavioral grouping.
- Parameterize when the assertion logic stays the same across many inputs.
- Keep parameter lists readable; if cases need custom setup or unrelated assertions, split them into separate tests.

## Async And Throwing Tests

- Mark tests `async`, `throws`, or both only when the code under test requires it.
- Await actual API boundaries instead of sleeping for timing-based coordination.
- Assert the behavior that matters, not incidental scheduling details.

## Traits, Tags, And Metadata

- Add tags when test selection or reporting benefits from stable categories.
- Add traits when they materially affect execution or metadata.
- Avoid metadata that adds ceremony without helping developers run, diagnose, or understand tests.

## Attachments And Diagnostics

- Add attachments only when they improve failure analysis.
- Prefer assertions that produce direct, localized failure messages.
- Regression tests should make the broken behavior obvious from the test name and inputs.

## Authoring Heuristics

- Match local repository style before introducing a new testing pattern.
- Keep setup close to the assertion until repetition clearly justifies helpers.
- If a repository still centers on XCTest, ask before mixing frameworks into the same area.
- Run the narrowest relevant test target first.

## Source Material

- Apple Swift Testing overview: https://developer.apple.com/documentation/Testing
- Meet Swift Testing: https://developer.apple.com/videos/play/wwdc2024/10179
- Go further with Swift Testing: https://developer.apple.com/videos/play/wwdc2024/10195
