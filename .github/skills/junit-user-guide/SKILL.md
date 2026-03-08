---
name: junit-user-guide
description: 'Use the JUnit User Guide to write or update JUnit Jupiter tests with correct annotations, assertions, parameterized tests, lifecycle methods, and extension usage. Trigger when asked to add tests, modernize existing JUnit tests, translate requirements into JUnit 5 or 6 test cases, or verify that test code follows current JUnit guidance. Also supports migration, build setup, and test execution troubleshooting when those block test authoring.'
argument-hint: 'Describe the JUnit test, migration, or test-runner problem to solve.'
---

# JUnit User Guide

Use this skill when the main deliverable is JUnit test code and the solution should follow the current JUnit User Guide instead of ad hoc conventions. Migration, build setup, and platform troubleshooting are supporting paths used only when they are necessary to get the test code right.

Load [the bundled JUnit reference map](./references/junit-reference-map.md) when you need a quick route from the user request to the right JUnit documentation area, build-tool guidance, or migration rule.

If the user knows the kind of JUnit task they have but not which prompt or asset fits best, load [the examples catalog](./references/examples-catalog.md).

## When to Use This Skill

- The user asks how to write or update JUnit tests.
- The user wants a failing or missing test turned into a correct Jupiter test.
- The user needs help migrating JUnit 4 code to JUnit Jupiter as part of updating tests.
- The user needs Maven, Gradle, IDE, or console launcher setup because it blocks test authoring.
- The user is dealing with JUnit Platform, Jupiter, or Vintage engine confusion that prevents tests from running.
- The user needs extension-model guidance to implement test fixtures or reusable test behavior.

## When Not to Use This Skill

- The task is about general Java unit testing theory without a concrete JUnit outcome.
- The user needs a framework-agnostic testing comparison rather than JUnit-specific guidance.
- The task is primarily about integration-test infrastructure, containers, or external test runners with only incidental JUnit usage.
- The user is building a custom testing framework and only loosely references JUnit.

## Core Principles

- Prefer JUnit Jupiter for new tests.
- Treat JUnit Vintage as temporary migration support, not a long-term target.
- Ground advice in the JUnit User Guide sections that match the request.
- Match the answer to the build tool, Java version, and execution environment actually present.
- Do not recommend APIs or dependencies that conflict with the detected JUnit generation.

## Prerequisites

Before making changes, identify:

- The build tool in use: Maven, Gradle, Ant, Bazel, or another setup.
- The current JUnit generation and artifacts already in the project.
- The Java runtime version. JUnit 6 requires Java 17 or newer at runtime.
- Whether the task is about writing tests, migration, running tests, extensions, or platform integration.

## Workflow

### Step 1: Classify the Test Authoring Task

Place the request into one primary category:

- Write new tests from requirements or code behavior
- Update or repair existing tests
- Migrate from JUnit 4
- Configure dependencies or build execution
- Troubleshoot execution or discovery
- Build extensions or platform integrations

If the request spans multiple categories, solve in this order:

1. Confirm execution environment and version constraints.
2. Resolve dependency or engine mismatches.
3. Implement or update the test code.
4. Address migration cleanup or extension design.

### Step 2: Inspect Local Project Context

Check the repository for:

- `pom.xml`, `build.gradle`, `build.gradle.kts`, or other build files
- Existing `org.junit.jupiter`, `org.junit.platform`, `org.junit`, or Vintage dependencies
- Test source layout and package conventions
- Existing assertions, lifecycle annotations, runners, or extensions
- The class or behavior the requested tests must cover

If the project context is missing, state the assumption before generating configuration or code.

### Step 3: Route to the Right JUnit Documentation Area

Use the request category to guide which parts of the User Guide matter most.

For writing or updating tests:

- Writing Tests in JUnit Jupiter
- Assertions
- Assumptions
- Parameterized tests
- Repeated tests
- Dynamic tests
- Test interfaces and lifecycle callbacks when shared behavior matters

For migration:

- Migrating from JUnit 4 to JUnit Jupiter
- Vintage engine guidance only when transitional support is required

For running tests:

- Build Support
- IDE Support
- Console Launcher
- JUnit Platform Suite Engine

For extensions and advanced use:

- Extension Model for JUnit Jupiter
- Launcher API
- Other platform verification APIs when explicitly requested

### Step 4: Apply Decision Rules

Use these rules consistently.

- If the user is creating new tests, target Jupiter unless a hard constraint says otherwise.
- If the user asks for tests but the production behavior is unclear, inspect the code first and derive test cases from observable behavior.
- If an existing test already expresses the project style, preserve that style unless it conflicts with current JUnit guidance.
- If JUnit 4 tests exist, migrate incrementally and use Vintage only as a bridge.
- If test discovery fails, verify the engine and dependency set before changing code.
- If the build tool is known, generate build-specific dependency and test-runner guidance.
- If the request involves custom runners, map that need to Jupiter extensions or suite support.
- If the runtime is below Java 17, do not assume JUnit 6 can be introduced without addressing runtime compatibility.

### Step 5: Produce the Output

Match the output shape to the request category.

- For test authoring, migration, build setup, troubleshooting, extensions, and platform work, the primary output is runnable code or concrete configuration changes.
- For review requests, the primary output is a findings-first analysis. Propose code changes only when the user asks for fixes or when a tiny example is necessary to explain the issue.

For code changes:

- Create or update test classes using Jupiter annotations and assertions.
- Keep naming, package structure, and style aligned with the repository.
- Cover the concrete behaviors the user asked for, including edge cases when they are visible in the source.
- Prefer readable assertions and parameterized tests over repetitive test duplication.

For migration advice:

- Explain the JUnit 4 construct being replaced.
- Show the Jupiter equivalent.
- Note any behavior changes, especially around lifecycle, assertions, and extensions.

For build or tooling setup:

- Provide the exact Maven or Gradle dependencies needed.
- Include how tests are executed in the detected environment.

For troubleshooting:

- Identify whether the failure is caused by dependency setup, platform discovery, engine selection, Java version, or test code behavior.
- Fix environment mismatches before rewriting tests.

For review requests:

- Present findings first, ordered by severity.
- Focus on correctness risks, brittle assertions, missing cases, outdated JUnit usage, and migration debt.
- Distinguish actual defects from style preferences.
- Include concrete file references when possible.

## What This Skill Should Produce

When invoked successfully, this skill should usually produce:

- One or more JUnit Jupiter test cases or test classes when the task is authoring or migration
- Small supporting dependency or configuration changes only if required for those tests to run
- A findings-first review when the task is test auditing rather than code generation
- A brief explanation of any migration or environment constraint that shaped the output

## Example Invocations

- Add JUnit Jupiter tests for `PriceCalculator`, covering discounts, zero quantities, and rounding behavior.
- Rewrite this JUnit 4 test class to Jupiter and remove deprecated runner usage.
- Turn these repetitive tests into a parameterized JUnit test and keep the existing naming style.
- Diagnose why this Maven project is not discovering Jupiter tests after I added `@Test` methods.
- Add a reusable JUnit extension for shared temporary-directory setup if the repository already uses extensions.

## Bundled Assets

- Parameterized test starter: [assets/parameterized-test-template.java.txt](./assets/parameterized-test-template.java.txt)
- Repeated test starter: [assets/repeated-test-template.java.txt](./assets/repeated-test-template.java.txt)
- Dynamic test starter: [assets/dynamic-test-template.java.txt](./assets/dynamic-test-template.java.txt)
- Exception assertion starter: [assets/exception-test-template.java.txt](./assets/exception-test-template.java.txt)
- Assumption-based test starter: [assets/assumption-test-template.java.txt](./assets/assumption-test-template.java.txt)
- Test interface starter: [assets/test-interface-template.java.txt](./assets/test-interface-template.java.txt)
- Suite starter: [assets/suite-template.java.txt](./assets/suite-template.java.txt)
- Launcher discovery starter: [assets/launcher-request-template.java.txt](./assets/launcher-request-template.java.txt)
- Extension-backed fixture starter: [assets/extension-fixture-template.java.txt](./assets/extension-fixture-template.java.txt)
- Maven dependency starter: [assets/maven-junit-jupiter-snippet.xml.txt](./assets/maven-junit-jupiter-snippet.xml.txt)
- Gradle dependency starter: [assets/gradle-junit-jupiter-snippet.gradle.txt](./assets/gradle-junit-jupiter-snippet.gradle.txt)

## Completion Checks

The task is complete only when all relevant checks pass.

- The chosen JUnit generation matches the repository constraints.
- New or updated test code uses Jupiter for modern test authoring unless there is an explicit reason not to.
- The produced tests map to concrete behavior, not placeholder assertions.
- The tests are structured so another engineer can understand why each scenario exists.
- Migration guidance does not leave the project stranded on deprecated Vintage usage without calling that out.
- Build instructions match the actual tool in the repository.
- Any Java version requirement that affects the solution is stated clearly.
- Explanations refer to the correct JUnit documentation area, not generic testing advice.

## Common Pitfalls

- Mixing JUnit 4 and Jupiter annotations in the same migration step without explaining the engine implications.
- Recommending Vintage for new test development.
- Ignoring the Java 17 runtime requirement for JUnit 6.
- Changing test code when the real issue is test engine discovery or missing dependencies.
- Giving Maven advice to a Gradle project or vice versa.
- Generating placeholder tests that only assert non-null or trivially mirror the implementation.

## References

- Bundled reference map: [references/junit-reference-map.md](./references/junit-reference-map.md)
- JUnit User Guide: https://docs.junit.org/
- Overview: https://docs.junit.org/6.0.3/overview.html
- Writing Tests in JUnit Jupiter: https://docs.junit.org/6.0.3/writing-tests/intro.html
- Migrating from JUnit 4: https://docs.junit.org/6.0.3/migrating-from-junit4.html
- Running Tests: https://docs.junit.org/6.0.3/running-tests/intro.html
- Extension Model: https://docs.junit.org/6.0.3/extensions/overview.html
- Launcher API: https://docs.junit.org/6.0.3/advanced-topics/launcher-api.html
