# JUnit Workspace Customizations

This folder contains a workspace-scoped JUnit skill and its supporting resources.

## Files

- [SKILL.md](./SKILL.md): Main workflow for JUnit Jupiter test authoring, migration, and troubleshooting.
- [references/junit-reference-map.md](./references/junit-reference-map.md): Compact routing guide for JUnit documentation topics.
- [references/examples-catalog.md](./references/examples-catalog.md): Prompt and asset routing guide for common JUnit tasks.
- [references/maintainer-guide.md](./references/maintainer-guide.md): Maintenance guide for extending the skill pack safely.
- [assets/parameterized-test-template.java.txt](./assets/parameterized-test-template.java.txt): Starter template for parameterized tests.
- [assets/repeated-test-template.java.txt](./assets/repeated-test-template.java.txt): Starter template for repeated tests.
- [assets/dynamic-test-template.java.txt](./assets/dynamic-test-template.java.txt): Starter template for dynamic tests.
- [assets/exception-test-template.java.txt](./assets/exception-test-template.java.txt): Starter template for exception assertions.
- [assets/assumption-test-template.java.txt](./assets/assumption-test-template.java.txt): Starter template for assumption-based tests.
- [assets/test-interface-template.java.txt](./assets/test-interface-template.java.txt): Starter template for shared test interfaces and lifecycle hooks.
- [assets/suite-template.java.txt](./assets/suite-template.java.txt): Starter template for JUnit Platform suites.
- [assets/launcher-request-template.java.txt](./assets/launcher-request-template.java.txt): Starter template for JUnit Platform discovery requests.
- [assets/extension-fixture-template.java.txt](./assets/extension-fixture-template.java.txt): Starter template for extension-managed fixtures.
- [assets/maven-junit-jupiter-snippet.xml.txt](./assets/maven-junit-jupiter-snippet.xml.txt): Starter Maven dependency and Surefire snippet.
- [assets/gradle-junit-jupiter-snippet.gradle.txt](./assets/gradle-junit-jupiter-snippet.gradle.txt): Starter Gradle dependency and test task snippet.

## Related Prompts

- [write-junit-tests.prompt.md](../prompts/write-junit-tests.prompt.md): Focused entry point for authoring or updating tests.
- [migrate-junit4-to-jupiter.prompt.md](../prompts/migrate-junit4-to-jupiter.prompt.md): Focused entry point for JUnit 4 migration.
- [diagnose-junit-test-discovery.prompt.md](../prompts/diagnose-junit-test-discovery.prompt.md): Focused entry point for discovery and execution failures.
- [configure-junit-build-support.prompt.md](../prompts/configure-junit-build-support.prompt.md): Focused entry point for Maven or Gradle setup.
- [review-junit-tests.prompt.md](../prompts/review-junit-tests.prompt.md): Focused entry point for test quality review.
- [write-exception-junit-tests.prompt.md](../prompts/write-exception-junit-tests.prompt.md): Focused entry point for exception and failure-path tests.
- [write-junit-assumptions.prompt.md](../prompts/write-junit-assumptions.prompt.md): Focused entry point for assumption-based tests.
- [write-parameterized-junit-tests.prompt.md](../prompts/write-parameterized-junit-tests.prompt.md): Focused entry point for parameterized tests.
- [write-repeated-junit-tests.prompt.md](../prompts/write-repeated-junit-tests.prompt.md): Focused entry point for repeated tests.
- [write-dynamic-junit-tests.prompt.md](../prompts/write-dynamic-junit-tests.prompt.md): Focused entry point for dynamic tests.
- [write-junit-test-interfaces.prompt.md](../prompts/write-junit-test-interfaces.prompt.md): Focused entry point for shared test interfaces.
- [write-junit-suite.prompt.md](../prompts/write-junit-suite.prompt.md): Focused entry point for JUnit Platform suites.
- [write-junit-launcher-tooling.prompt.md](../prompts/write-junit-launcher-tooling.prompt.md): Focused entry point for Launcher API and related platform tooling.
- [write-junit-extension.prompt.md](../prompts/write-junit-extension.prompt.md): Focused entry point for Jupiter extensions.

## Intended Use

Use the prompts for common entry points and let them route through the skill. Use the skill directly when the task is broader and needs the full JUnit workflow.

If you are unsure which prompt to use first, start with [references/examples-catalog.md](./references/examples-catalog.md).

Use the JUnit skill directly when one request spans multiple categories, such as migration plus build setup plus new test authoring.

## Template Format Note

The starter Java snippets are stored as `.java.txt` files on purpose. This repository is a Copilot customization pack rather than a buildable Java project, so keeping them as text assets avoids false language-service and compile errors while still providing copyable starter code.

For pack maintenance and final cross-file verification, use [references/maintainer-guide.md](./references/maintainer-guide.md). Its release checklist is the canonical close-out process for pack changes.

## Try It

- Use `/Write JUnit Tests` for general test authoring.
- Use `/Migrate JUnit 4 To Jupiter` for migration work.
- Use `/Diagnose JUnit Test Discovery` for missing or skipped tests.
- Use `/Configure JUnit Build Support` for Maven or Gradle setup.
- Use `/Review JUnit Tests` for brittleness, gap, and migration review.
- Use `/Write Exception JUnit Tests` for validation failures and thrown exceptions.
- Use `/Write JUnit Assumptions` for conditional test execution based on runtime preconditions.
- Use `/Write Parameterized JUnit Tests` for repetitive test consolidation.
- Use `/Write Repeated JUnit Tests` for deliberate repeated invocations or repetition-aware assertions.
- Use `/Write Dynamic JUnit Tests` for runtime-generated case sets.
- Use `/Write JUnit Test Interfaces` for shared test contracts and lifecycle reuse.
- Use `/Write JUnit Suite` for package, tag, or class-based suite composition.
- Use `/Write JUnit Launcher Tooling` for custom discovery, execution, or other platform-level tooling.
- Use `/Write JUnit Extension` for reusable Jupiter lifecycle behavior.
- Use the JUnit skill directly for multi-step work that does not fit one focused prompt.
