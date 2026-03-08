---
name: gradle-best-practices
description: 'Review, modernize, and refactor Gradle builds using official Gradle best practices. Use when working on build.gradle, build.gradle.kts, settings.gradle, settings.gradle.kts, gradle.properties, gradle wrapper files, version catalogs, convention plugins, buildSrc, build-logic, dependency repositories, custom tasks, build cache, configuration cache, or Gradle upgrade hygiene.'
---

# Gradle Best Practices

Use this skill to audit or improve a Gradle build against the current official Gradle best-practices guidance.

Keep the work practical. Prefer focused fixes over broad churn, and preserve existing behavior unless the user asks for structural changes.

See [references/gradle-best-practices.md](references/gradle-best-practices.md) for the condensed rulebook this workflow applies.

## When to Use This Skill

- Reviewing a Gradle build for maintainability, performance, or security issues
- Modernizing an older Gradle build toward current idioms
- Refactoring duplicated or fragile build logic
- Evaluating `buildSrc`, convention plugins, version catalogs, wrapper configuration, or custom task implementations
- Preparing or validating a Gradle upgrade

## Scope First

Before proposing edits, determine which of these modes best matches the request:

1. Audit only
2. Audit and patch
3. Create a new Gradle build skeleton aligned with best practices
4. Review one area only: structure, dependencies, tasks, performance, or security

If the user did not specify a mode, default to audit and patch for the files in scope.

## Workflow

### Step 1: Inventory the Build

Inspect the repository for these files and directories when present:

- `settings.gradle` or `settings.gradle.kts`
- `build.gradle` or `build.gradle.kts`
- subproject build files
- `gradle.properties`
- `gradle/libs.versions.toml`
- `gradle/wrapper/gradle-wrapper.properties`
- `buildSrc/`
- `build-logic/`
- CI files that validate the wrapper

Record whether the build uses Groovy DSL or Kotlin DSL, whether it is single-project or multi-project, and whether custom plugins or custom tasks exist.

### Step 2: Classify Findings

Sort issues into these buckets:

1. Structure
2. Dependencies and repositories
3. Tasks and lazy configuration
4. Performance
5. Security
6. Upgrade readiness

Prioritize root-cause issues that affect multiple projects or block configuration-cache, caching, or safe upgrades.

### Step 3: Apply Decision Logic

Use these branches while evaluating the build:

- If this is a new build or a newly added module, prefer Kotlin DSL.
- If the build already uses Groovy DSL and the user did not ask for migration, do not force a DSL rewrite.
- If common logic is duplicated across projects, prefer convention plugins.
- If shared build logic lives in `buildSrc`, consider moving it to an included `build-logic` build unless the user needs a minimal prototype or the migration cost clearly outweighs the benefit.
- If repositories are declared in project build files, move them to settings unless there is a deliberate exception.
- If multiple repositories are required, add repository content filtering and be explicit about any fallback repository risk.
- If dependency versions are scattered across build scripts, centralize them in a version catalog.
- If custom tasks use eager APIs, `dependsOn` for data flow, provider `.get()` during configuration, manual configuration resolution, or overlapping outputs, refactor to lazy task wiring.
- If wrapper files are touched or Gradle is upgraded, treat wrapper validation and checksum verification as mandatory.
- If enabling configuration cache would likely break the build, surface the blockers first instead of forcing the flag on blindly.

### Step 4: Make Focused Changes

Prefer small, defensible edits such as:

- naming the root project
- using the `plugins` block
- moving repositories to settings
- introducing `libs.versions.toml`
- moving duplicate logic into convention plugins
- replacing brittle task wiring with inputs and outputs
- setting stable flags in `gradle.properties`
- switching wrapper distribution from `-all` to `-bin` when appropriate
- adding `distributionSha256Sum`
- adding CI wrapper validation

Avoid speculative rewrites that are not justified by the current build.

### Step 5: Verify

After changes, run the narrowest useful verification available. Prefer one or more of:

- Gradle help or tasks listing for configuration sanity
- the specific task or build the user cares about
- a configuration-cache run if relevant to the change
- wrapper validation if wrapper files changed

If verification cannot run, say exactly why.

## Completion Checks

The work is complete when all applicable items below are either satisfied, intentionally deferred, or explicitly called out:

- Root project is explicitly named
- Plugin application uses modern patterns and avoids order assumptions
- Repositories are centralized in settings when applicable
- Dependency versions are centralized and naming is coherent
- Common build logic is not duplicated unnecessarily
- Custom tasks use lazy APIs and correct inputs and outputs
- No obvious eager configuration or premature dependency resolution remains in touched code
- Performance flags and cache settings are deliberate, not accidental
- Wrapper integrity and upgrade hygiene are covered if wrapper files changed
- The user gets a concise explanation of what changed, what was verified, and what remains risky

## Output Style

When asked for a review, lead with findings ordered by severity. When asked to patch, implement the fixes first and then summarize the result.

For each significant recommendation or change, state:

- what is wrong
- why it matters in Gradle terms
- the smallest reasonable fix

## Example Prompts

- Review this Gradle build against current best practices.
- Move this multi-project build away from `buildSrc` if it makes sense.
- Refactor these custom tasks so they are configuration-cache friendly.
- Centralize versions and repositories in this Gradle build.
- Check whether this wrapper upgrade is safe and complete.

## References

- [references/gradle-best-practices.md](references/gradle-best-practices.md)
- <https://docs.gradle.org/current/userguide/best_practices.html>