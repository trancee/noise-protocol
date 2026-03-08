# JUnit Examples Catalog

Use this file when you know the kind of JUnit task you have but are not sure which prompt or asset should be used first.

## Use The Full Skill Directly

Use [../SKILL.md](../SKILL.md) directly instead of a focused prompt when the task spans multiple categories, such as migration plus build setup plus new test authoring.

- Use when: You do not have a single narrow prompt that matches the whole job.
- Example: `Use the JUnit skill to migrate LegacyOrderServiceTest from JUnit 4, fix Maven Jupiter setup, and add missing edge-case tests.`

## Test Authoring

Write ordinary Jupiter tests:

- Prompt: [../../prompts/write-junit-tests.prompt.md](../../prompts/write-junit-tests.prompt.md)
- Use when: You need new tests for a class, method, or bug fix.
- Example: `/Write JUnit Tests add coverage for PriceCalculator rounding edge cases`

Write exception and failure-path tests:

- Prompt: [../../prompts/write-exception-junit-tests.prompt.md](../../prompts/write-exception-junit-tests.prompt.md)
- Asset: [../assets/exception-test-template.java.txt](../assets/exception-test-template.java.txt)
- Use when: You need `assertThrows` or failure-condition coverage.
- Example: `/Write Exception JUnit Tests verify UserValidator rejects empty email`

Write assumption-based tests:

- Prompt: [../../prompts/write-junit-assumptions.prompt.md](../../prompts/write-junit-assumptions.prompt.md)
- Asset: [../assets/assumption-test-template.java.txt](../assets/assumption-test-template.java.txt)
- Use when: A test should abort unless an environment or runtime precondition holds.
- Example: `/Write JUnit Assumptions skip docker-backed tests unless Docker is available`

## Repetition And Data-Driven Tests

Write parameterized tests:

- Prompt: [../../prompts/write-parameterized-junit-tests.prompt.md](../../prompts/write-parameterized-junit-tests.prompt.md)
- Asset: [../assets/parameterized-test-template.java.txt](../assets/parameterized-test-template.java.txt)
- Use when: Similar cases differ only by inputs and expected outputs.
- Example: `/Write Parameterized JUnit Tests refactor duplicate parser cases`

Write repeated tests:

- Prompt: [../../prompts/write-repeated-junit-tests.prompt.md](../../prompts/write-repeated-junit-tests.prompt.md)
- Asset: [../assets/repeated-test-template.java.txt](../assets/repeated-test-template.java.txt)
- Use when: The test is intentionally about repeated invocations or repetition-aware state.
- Example: `/Write Repeated JUnit Tests verify repetition-aware cache warmup state across three invocations`

Write dynamic tests:

- Prompt: [../../prompts/write-dynamic-junit-tests.prompt.md](../../prompts/write-dynamic-junit-tests.prompt.md)
- Asset: [../assets/dynamic-test-template.java.txt](../assets/dynamic-test-template.java.txt)
- Use when: Test cases are generated programmatically at runtime.
- Example: `/Write Dynamic JUnit Tests generate parser checks from sample fixtures`

## Shared Structure And Reuse

Write shared test interfaces:

- Prompt: [../../prompts/write-junit-test-interfaces.prompt.md](../../prompts/write-junit-test-interfaces.prompt.md)
- Asset: [../assets/test-interface-template.java.txt](../assets/test-interface-template.java.txt)
- Use when: Multiple test classes should share the same contract or lifecycle hooks.
- Example: `/Write JUnit Test Interfaces extract shared repository contract tests`

Write extensions:

- Prompt: [../../prompts/write-junit-extension.prompt.md](../../prompts/write-junit-extension.prompt.md)
- Asset: [../assets/extension-fixture-template.java.txt](../assets/extension-fixture-template.java.txt)
- Use when: Setup or lifecycle logic should be reusable across tests.
- Example: `/Write JUnit Extension add reusable before-each database reset hook`

## Migration And Configuration

Migrate JUnit 4 to Jupiter:

- Prompt: [../../prompts/migrate-junit4-to-jupiter.prompt.md](../../prompts/migrate-junit4-to-jupiter.prompt.md)
- Use when: A legacy test still uses JUnit 4 annotations, rules, or runners.
- Example: `/Migrate JUnit 4 To Jupiter convert LegacyOrderServiceTest`

Configure Maven or Gradle support:

- Prompt: [../../prompts/configure-junit-build-support.prompt.md](../../prompts/configure-junit-build-support.prompt.md)
- Assets:
  - [../assets/maven-junit-jupiter-snippet.xml.txt](../assets/maven-junit-jupiter-snippet.xml.txt)
  - [../assets/gradle-junit-jupiter-snippet.gradle.txt](../assets/gradle-junit-jupiter-snippet.gradle.txt)
- Use when: JUnit dependencies or Platform execution are missing.
- Example: `/Configure JUnit Build Support enable JUnit Platform in Gradle`

Diagnose discovery problems:

- Prompt: [../../prompts/diagnose-junit-test-discovery.prompt.md](../../prompts/diagnose-junit-test-discovery.prompt.md)
- Use when: Tests are not discovered, skipped unexpectedly, or fail to run.
- Example: `/Diagnose JUnit Test Discovery Maven build does not run Jupiter tests`

## Platform-Level Work

Write JUnit suites:

- Prompt: [../../prompts/write-junit-suite.prompt.md](../../prompts/write-junit-suite.prompt.md)
- Asset: [../assets/suite-template.java.txt](../assets/suite-template.java.txt)
- Use when: Tests should be grouped by tag, package, class, or engine selection rules.
- Example: `/Write JUnit Suite group repository integration tests by tag`

Write Launcher API or related platform tooling code:

- Prompt: [../../prompts/write-junit-launcher-tooling.prompt.md](../../prompts/write-junit-launcher-tooling.prompt.md)
- Asset: [../assets/launcher-request-template.java.txt](../assets/launcher-request-template.java.txt)
- Use when: You need custom test discovery requests, execution listeners, or other platform-level verification code.
- Note: If you need JUnit Platform Test Kit specifically, ask for it explicitly because this pack only bundles a launcher-request starter.
- Example: `/Write JUnit Launcher Tooling build a discovery request for repository tests`

## Review Work

Review test quality:

- Prompt: [../../prompts/review-junit-tests.prompt.md](../../prompts/review-junit-tests.prompt.md)
- Use when: You want findings about brittleness, missing coverage, or outdated JUnit usage.
- Example: `/Review JUnit Tests audit CartServiceTest for brittle assertions`
