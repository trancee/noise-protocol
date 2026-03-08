# XCTest To Swift Testing Examples

Use these examples to keep migrations behavior-preserving while moving toward native Swift Testing structure.

## Basic Assertion Migration

XCTest:

```swift
final class SlugFormatterTests: XCTestCase {
    func testBlankInputProducesEmptySlug() {
        XCTAssertEqual(SlugFormatter().format("   "), "")
    }
}
```

Swift Testing:

```swift
import Testing
@testable import YourModule

@Test("Blank input produces an empty slug")
func blankInputProducesEmptySlug() {
    #expect(SlugFormatter().format("   ") == "")
}
```

## `XCTAssertNotNil` To `#require`

XCTest:

```swift
func testLoadsDefaultProfile() {
    let profile = store.defaultProfile()

    XCTAssertNotNil(profile)
    XCTAssertEqual(profile?.name, "Guest")
}
```

Swift Testing:

```swift
@Test("Loads the default profile")
func loadsDefaultProfile() throws {
    let profile = try #require(store.defaultProfile())

    #expect(profile.name == "Guest")
}
```

## Async Expectation Migration

XCTest:

```swift
func testRefreshUpdatesCache() {
    let expectation = expectation(description: "refresh")

    client.refresh {
        expectation.fulfill()
    }

    wait(for: [expectation], timeout: 1)
    XCTAssertEqual(cache.version, 2)
}
```

Swift Testing:

```swift
@Test("Refresh updates the cache")
func refreshUpdatesCache() async throws {
    try await client.refresh()

    #expect(cache.version == 2)
}
```

## Setup-Heavy Class Migration

XCTest:

```swift
final class CurrencyConverterTests: XCTestCase {
    var converter: CurrencyConverter!

    override func setUp() {
        converter = CurrencyConverter(rates: ["USD:EUR": 0.92])
    }

    func testAppliesConfiguredRate() throws {
        XCTAssertEqual(try converter.convert(100, from: "USD", to: "EUR"), 92)
    }
}
```

Swift Testing:

```swift
import Testing
@testable import YourModule

@Suite("Currency conversion")
struct CurrencyConverterTests {
    @Test("Applies the configured rate")
    func appliesConfiguredRate() throws {
        let converter = CurrencyConverter(rates: ["USD:EUR": 0.92])

        #expect(try converter.convert(100, from: "USD", to: "EUR") == 92)
    }
}
```

## Migration Heuristic

- Keep the first pass close to original behavior.
- Remove XCTest lifecycle ceremony when local setup is clearer.
- If the original test was weak, call that out separately rather than silently redefining the test during migration.
