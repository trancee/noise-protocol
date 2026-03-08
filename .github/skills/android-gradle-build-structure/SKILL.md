---
name: android-gradle-build-structure
description: 'Explain an Android project''s Gradle build structure. Use when inspecting settings.gradle, build.gradle, build.gradle.kts, gradle.properties, modules, plugins, repositories, dependencies, tasks, and build variants in an Android repo.'
argument-hint: 'Path or scope to inspect, plus any focus such as modules, variants, dependencies, or tasks'
user-invocable: true
---

# Android Gradle Build Structure

Use this skill to inspect and explain how an Android project's Gradle build is organized.

## What This Skill Produces

- A concise architecture summary of the build layout across root and module files
- A mapping of modules, plugins, repositories, dependencies, and variants
- A short explanation of how Gradle's initialization, configuration, and execution phases apply to the project
- A concise summary of likely build outputs and the main tasks involved

## When to Use

- A repo has Android Gradle files and you need to understand how the build is wired
- You need to explain what each module does and how modules depend on each other
- You need to identify where plugins, SDK versions, signing, flavors, or build types are defined
- You need to trace which tasks and variants are expected from the current configuration

## Example Prompts

- Explain the Gradle build structure of this Android repo
- Summarize the modules, plugins, and dependency management for this project
- Focus on build variants, source sets, and likely outputs
- Inspect this project and explain which Gradle files control plugin resolution and module inclusion

## Procedure

1. Identify the build entry points.
   Look for `settings.gradle` or `settings.gradle.kts`, root `build.gradle` or `build.gradle.kts`, `gradle.properties`, `gradle/libs.versions.toml`, `gradle/wrapper/gradle-wrapper.properties`, and module-level build files.

2. Determine the project shape.
   Decide whether the project is single-module or multi-module. List included modules from the settings file and classify each one as app, library, feature, test-only, or support infrastructure based on its applied plugins and Android block.

3. Identify the active plugins and conventions.
   Record which plugins are applied at the root and per module, including Android application or library plugins, Kotlin plugins, publishing plugins, and convention plugins. Note whether the project uses Kotlin DSL or Groovy DSL.

4. Explain the build lifecycle in project terms.
   Map Gradle's three phases to the repo:
   - Initialization: which projects are included and where plugin or dependency repositories are declared
   - Configuration: which build files register and configure tasks, plugins, Android options, and dependencies
   - Execution: which requested tasks run and which outputs they generate

5. Map repositories and dependency management.
   Explain where repositories are declared, whether a version catalog is used, and how external and project dependencies are declared. Distinguish between module dependencies and external Maven coordinates.

6. Extract Android configuration.
   For each Android module, summarize namespace, compile SDK, minimum SDK, target SDK, default config, signing, build features, packaging, and any custom Android options that materially affect the build.
   Separate configured files or hooks from enabled behavior. Do not imply minification, signing, publishing, shrinking, or similar release features are active unless the corresponding flags or applied plugins explicitly enable them.

7. Enumerate variants.
   Identify build types and product flavors. If flavors exist, describe the variant matrix using the `<flavor><BuildType>` naming pattern. Explain which source sets are shared and which override behavior.

8. Connect tasks to outputs.
   Infer the main tasks a developer would run, such as assemble, bundle, test, lint, or publish tasks. If Gradle commands are allowed and the wrapper is present, confirm with safe discovery commands such as `./gradlew projects`, `./gradlew tasks --all`, or `./gradlew help --task <taskName>`. Prefer discovery commands that do not mutate the project state. State the expected outputs, such as APK, AAB, AAR, reports, or generated sources.

9. Deliver the explanation in a stable format.
   Use these sections in order:
   - Project shape
   - Root build configuration
   - Module summary
   - Repositories and dependencies
   - Variants and source sets
   - Key tasks and outputs
   - Open questions or ambiguities
   Keep the default response concise. Expand into module-by-module detail only when the repo is complex or the user asks for it.
   Use the bundled [summary template](./assets/summary-template.md) unless the user asks for a different output format.
   If the user asks for a deeper inspection, switch to the [module audit template](./assets/module-audit-template.md).

## Decision Points

- If both Kotlin and Groovy files exist, prefer the file Gradle actually uses in that module and note duplicates as potential confusion.
- If convention plugins or `buildSrc` are present, treat them as part of the build definition and inspect them before summarizing behavior.
- If a version catalog exists, use it as the source of truth for dependency coordinates when possible.
- If no flavors are defined, state that variants are build-type-only rather than implying missing configuration.
- If custom tasks exist, explain only tasks that affect build outputs or developer workflow in a material way.
- If Gradle commands are available, use them to confirm ambiguous task or project structure claims instead of guessing.
- If a module references ProGuard files, signing files, packaging rules, or publishing blocks, describe them as configured inputs unless the related feature is clearly enabled.
- Do not run mutating or release-oriented commands such as publish, clean as a fix, signing, upload, or deployment tasks unless the user explicitly asks.
- Prefer the safe discovery command set in [safe Gradle discovery](./references/safe-gradle-discovery.md) before inventing ad hoc commands.

## Completion Checks

- Every included module is accounted for
- Plugin ownership is clear at root and module scope
- Repositories and dependency sources are identified
- Build types and flavors are explicitly called out, including when absent
- Expected outputs are tied to likely tasks
- Configured files are not overstated as enabled features
- Unknown or inferred behavior is labeled as such

## Reference

- [Gradle build overview](./references/gradle-build-overview.md)
- [Safe Gradle discovery](./references/safe-gradle-discovery.md)
- [Summary template](./assets/summary-template.md)
- [Module audit template](./assets/module-audit-template.md)
