---
name: android-gradle-troubleshooting
description: 'Troubleshoot Android Gradle sync, configuration, dependency, task, plugin, and variant failures. Use when an Android repo has build errors, sync errors, missing tasks, repository problems, or variant resolution issues.'
argument-hint: 'Error message, failing task, or area to investigate such as sync, dependencies, plugins, or variants'
user-invocable: true
---

# Android Gradle Troubleshooting

Use this skill to diagnose Android Gradle problems methodically and produce a focused root-cause summary.

## What This Skill Produces

- A short diagnosis of the most likely root cause
- The smallest set of files, settings, or tasks that need inspection or change
- Safe verification steps to confirm the diagnosis
- Clear unknowns when the evidence is incomplete

## When to Use

- Android Studio sync fails
- Gradle configuration or task execution fails
- A plugin, repository, or dependency cannot be resolved
- A variant, source set, or module dependency behaves unexpectedly
- A known task is missing or a custom task behaves differently than expected

## Example Prompts

- Troubleshoot this Android Gradle sync failure
- Diagnose why this dependency cannot be resolved in my Android build
- Explain why the `assembleDebug` task is missing from this project
- Investigate this build variant mismatch in an Android multi-module repo

## Procedure

1. Classify the failure.
   Identify whether the issue is primarily a sync, configuration, dependency resolution, plugin resolution, task graph, module inclusion, variant, signing, or environment problem.

2. Capture the exact symptom.
   Quote the failing command, task name, and the smallest relevant error text. Prefer the first actionable failure over later cascading errors.

3. Inspect the build definition first.
   Read `settings.gradle` or `settings.gradle.kts`, root and module `build.gradle` or `build.gradle.kts`, `gradle.properties`, version catalogs, and wrapper configuration before proposing changes.

4. Trace ownership.
   Determine where the failing behavior is defined:
   - plugin management or dependency resolution in settings
   - shared configuration at root or via convention plugins
   - module-specific Android or dependency configuration
   - environment constraints such as Gradle, Java, AGP, or repository access
   If the failure is a mismatch between two modules or variants, name every owner file that participates in the mismatch rather than attributing it to only the provider or only the consumer.

5. Confirm with safe commands only when needed.
   Use the commands in [safe troubleshooting commands](./references/safe-troubleshooting-commands.md) to confirm whether projects, tasks, properties, or dependency resolution behave as expected.

6. Reduce to root cause.
   Distinguish the primary issue from follow-on failures. Prefer explanations such as version mismatch, missing repository, wrong plugin application site, missing module include, invalid variant expectation, or incompatible toolchain.

7. Propose the narrowest fix.
   Recommend the smallest configuration change or verification step that addresses the root cause. Avoid broad resets or speculative edits.

8. Deliver the diagnosis in a stable format.
   Use the bundled [diagnosis template](./assets/diagnosis-template.md) unless the user asks for another structure.

## Decision Points

- If both sync errors and compile errors appear, diagnose sync or configuration failures first because they often invalidate downstream errors.
- If a task is missing, inspect plugin application and variant generation before assuming task naming changed.
- If a dependency cannot be resolved, inspect repositories, version catalogs, coordinates, and dependency scope before blaming the network.
- If a variant is missing, inspect build types, product flavors, source sets, and AGP variant naming rules before suggesting new variants.
- If two modules define incompatible flavors or variants, identify both sides of the mismatch and cite both owner files before proposing a fix.
- If Java, Gradle, Kotlin, or AGP versions conflict, treat toolchain compatibility as the primary suspect.
- If environment or credential issues are possible, label them clearly as environmental rather than build-script defects unless the files prove otherwise.

## Completion Checks

- The primary failure is named and distinguished from secondary failures
- Every owner file or configuration area involved in the mismatch is identified
- Proposed verification uses safe commands or targeted inspection
- The suggested fix is minimal and directly connected to the evidence
- Unverified assumptions are explicitly labeled

## Reference

- [Safe troubleshooting commands](./references/safe-troubleshooting-commands.md)
- [Diagnosis template](./assets/diagnosis-template.md)
