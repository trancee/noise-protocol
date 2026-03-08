# XCTest To Swift Testing Mapping

Use this reference when converting common XCTest patterns to Swift Testing.

## Structural Mapping

- `final class SomeTests: XCTestCase` -> free `@Test` functions or an `@Suite` type when grouping is still useful.
- `setUp()` and `tearDown()` -> prefer local setup inside each test unless repeated fixture creation clearly justifies a helper.
- Shared mutable instance state -> prefer explicit local values so tests stay isolated and parallel-safe.

## Assertion Mapping

- `XCTAssertEqual(a, b)` -> `#expect(a == b)`
- `XCTAssertNotEqual(a, b)` -> `#expect(a != b)`
- `XCTAssertTrue(value)` -> `#expect(value)`
- `XCTAssertFalse(value)` -> `#expect(!value)`
- `XCTAssertNil(value)` -> `#expect(value == nil)`
- `XCTAssertNotNil(value)` -> use `let value = try #require(value)` when later assertions depend on it, otherwise `#expect(value != nil)`
- `XCTFail("message")` -> prefer an explicit failing expectation that states the violated behavior

## Error And Throwing Mapping

- `XCTAssertThrowsError` -> express the expected throwing behavior directly with Swift Testing's throwing expectations where appropriate in the local style.
- `XCTAssertNoThrow` -> often unnecessary when the test itself is not marked `throws`; otherwise assert the successful result that matters.
- Throwing test methods -> mark the Swift Testing function `throws` only when it clarifies the path under test.

## Async Mapping

- `expectation(description:)` plus `wait(for:)` -> prefer `async` tests with direct `await` on the behavior under test.
- Callback plumbing retained only for legacy APIs that cannot yet expose an async boundary.
- Sleep-based synchronization -> remove and replace with awaited state transitions or direct async calls.

## Migration Heuristics

- Preserve behavior first; improve style second.
- If a lifecycle hook exists only to build one fixture, move that setup into each relevant test.
- If migration reveals that a test only checks incidental state, flag it as a follow-up rather than silently redefining the test's purpose.
- Keep diffs reviewable by avoiding unrelated production refactors inside the same migration.

## Bias Checks

- Do not recreate class inheritance patterns without a current reason.
- Do not parameterize tests during migration unless the original cases already share one clean assertion shape.
- Do not assume every XCTest idiom needs a one-to-one Swift Testing equivalent.
- Do not treat migration as complete if the assertions became less meaningful.
