# Swift Testing Authoring Patterns

Use these patterns as starting points. Adapt names, fixtures, and assertions to the local codebase instead of copying them mechanically.

## Single-Behavior Test

```swift
import Testing
@testable import YourModule

@Test("Returns an empty slug for blank input")
func blankInputProducesEmptySlug() {
    let result = SlugFormatter().format("   ")

    #expect(result == "")
}
```

Use this shape when one clear behavior can be explained by a short setup and one or two expectations.

## Suite With Related Behaviors

```swift
import Testing
@testable import YourModule

@Suite("Currency conversion")
struct CurrencyConverterTests {
    @Test("Uses the configured exchange rate")
    func appliesConfiguredRate() throws {
        let converter = CurrencyConverter(rates: ["USD:EUR": 0.92])

        let result = try converter.convert(100, from: "USD", to: "EUR")

        #expect(result == 92)
    }

    @Test("Rejects missing exchange rates")
    func rejectsUnknownRate() {
        let converter = CurrencyConverter(rates: [:])

        #expect(throws: ConversionError.self) {
            try converter.convert(100, from: "USD", to: "EUR")
        }
    }
}
```

Use a suite when several tests share a feature area and the grouping helps navigation or intent.

## Parameterized Test

```swift
import Testing
@testable import YourModule

@Test(
    "Normalizes user-visible names",
    arguments: [
        (" Ada Lovelace ", "ada-lovelace"),
        ("Hello, World!", "hello-world"),
        ("Swift_Testing", "swift-testing")
    ]
)
func normalizesDisplayNames(input: String, expected: String) {
    let result = SlugFormatter().format(input)

    #expect(result == expected)
}
```

Use parameterization when the assertion logic is identical across cases and the case list makes failures easier to localize.

## Test With `#require`

```swift
import Testing
@testable import YourModule

@Test("Loads the default profile from seeded storage")
func loadsDefaultProfile() throws {
    let store = ProfileStore(seed: [.defaultProfile])
    let profile = try #require(store.defaultProfile())

    #expect(profile.id == .default)
    #expect(profile.name == "Guest")
}
```

Use `#require` when later assertions are meaningless unless a value exists.

## Async Test

```swift
import Testing
@testable import YourModule

@Test("Refreshes cached data after a successful fetch")
func refreshesCacheAfterFetch() async throws {
    let client = APIClient(transport: .mockSuccess(["version": 2]))
    let cache = DataCache()

    try await client.refresh(cache: cache)

    #expect(cache.version == 2)
}
```

Prefer awaiting the real async API boundary instead of introducing sleeps or timing assumptions.

## Regression Test Skeleton

```swift
import Testing
@testable import YourModule

@Test("Regression: parser preserves quoted commas")
func parserPreservesQuotedCommas() throws {
    let input = #"name,"last, first",role"#

    let fields = try CSVParser().parseLine(input)

    #expect(fields == ["name", "last, first", "role"])
}
```

For regressions, put the broken input and the expected behavior directly in the test so the failure communicates the bug clearly.

## Adaptation Rules

- Replace placeholder module and type names with real local symbols.
- Match nearby test file naming and import style.
- Keep fixtures inline until repetition makes the test harder to read.
- Do not import or introduce XCTest APIs unless the repository convention requires them.
