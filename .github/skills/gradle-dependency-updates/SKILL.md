---
name: gradle-dependency-updates
description: 'Review and update Gradle dependencies, plugins, version catalogs, and wrapper versions with a conservative workflow. Use when checking outdated Gradle dependencies, updating libs.versions.toml, upgrading plugin versions, reviewing version drift, or preparing safe Gradle dependency update changes.'
---

# Gradle Dependency Updates

Use this skill to review or update dependency and plugin versions in Gradle builds with a bias toward conservative, explainable changes.

Keep updates focused. Prefer small version moves, preserve intentional pins unless the user asks otherwise, and separate dependency-version work from unrelated Gradle modernization.

See [references/gradle-dependency-updates.md](references/gradle-dependency-updates.md) for the condensed rulebook this workflow applies.

## When to Use This Skill

- Reviewing outdated Gradle dependencies or plugins
- Updating `gradle/libs.versions.toml`
- Consolidating scattered dependency versions into a version catalog
- Auditing version drift across modules
- Preparing a wrapper, plugin, or library update with minimal unrelated churn

## Scope First

Before making changes, determine which mode applies:

1. Audit only
2. Audit and patch safe updates
3. Centralize versions without changing effective versions
4. Review one area only: libraries, plugins, version catalog, or wrapper

If the user did not specify a mode, default to audit and patch only for clearly safe, low-risk updates in scope.

## Workflow

### Step 1: Inventory Version Sources

Inspect the build for version declarations in any of these places:

- `gradle/libs.versions.toml`
- `plugins` blocks in build or settings files
- inline dependency strings in build files
- extra properties, local variables, or `ext` blocks
- wrapper version in `gradle/wrapper/gradle-wrapper.properties`

Record whether versions are centralized or scattered.

### Step 2: Classify Updates

Sort candidate changes into these groups:

1. Patch updates
2. Minor updates
3. Major updates
4. Centralization-only changes
5. Security- or compatibility-sensitive changes

Treat wrapper updates, plugin major updates, and Kotlin or Android ecosystem updates as higher-risk than ordinary library patch bumps.

### Step 3: Apply Decision Logic

- If the build already uses a version catalog, prefer updating it there instead of editing repeated inline versions.
- If versions are scattered across build files, prefer centralization before broad upgrades unless the user explicitly wants direct updates only.
- If a version appears intentionally pinned or constrained, preserve it unless the user asks to revisit the pin.
- If the update is major and could change public behavior, surface it separately instead of silently applying it.
- If wrapper, Gradle plugin, Kotlin plugin, or Android plugin versions move together, call out compatibility as a distinct review item.
- If a dependency update would require structural build changes, separate the version bump from the structural refactor where practical.

### Step 4: Make Focused Changes

Prefer edits such as:

- updating aliases in `libs.versions.toml`
- replacing duplicated inline versions with catalog aliases
- aligning plugin versions in a single place
- removing redundant duplicate dependency declarations
- keeping version changes grouped by ecosystem or risk level

Avoid mixing broad cleanup with dependency updates unless the user asked for it.

### Step 5: Verify

After changes, run the narrowest useful verification available, such as:

- dependency resolution sanity checks
- the specific module build or test task affected by the updated dependency
- wrapper or plugin validation if those versions changed

If verification cannot run, say exactly why.

## Completion Checks

The work is complete when applicable items are satisfied, intentionally deferred, or explicitly called out:

- version sources in scope are identified
- scattered versions are centralized when appropriate
- safe updates are grouped and explained clearly
- major or compatibility-sensitive updates are separated from routine updates
- no unnecessary unrelated refactors are mixed into the change
- the user gets a concise summary of what changed, what was verified, and what remains risky

## Output Style

When asked for a review, present findings first and group them by risk level. When asked to patch, make the conservative edits first and then summarize the result.

For each significant recommendation or change, state:

- what changed or should change
- why it matters in Gradle terms
- whether it is routine, compatibility-sensitive, or intentionally deferred

## Example Prompts

- Review this Gradle build for dependency version drift.
- Update safe dependency versions in this version catalog.
- Centralize scattered plugin and library versions in this Gradle build.
- Review whether this Gradle wrapper and plugin version set is coherent.

## References

- [references/gradle-dependency-updates.md](references/gradle-dependency-updates.md)
- [../gradle-best-practices/references/gradle-best-practices.md](../gradle-best-practices/references/gradle-best-practices.md)