# Gradle Dependency Updates Reference

This reference condenses the repository's intended workflow for conservative Gradle dependency and plugin updates.

## Core rules

- Prefer updating versions in `gradle/libs.versions.toml` when a version catalog exists.
- Prefer centralizing scattered versions before broad upgrade work when the build is currently fragmented.
- Keep routine library updates separate from structural build refactors.
- Treat wrapper, Gradle plugin, Kotlin plugin, and Android plugin updates as compatibility-sensitive.
- Preserve intentional pins, constraints, and strict versions unless the user asks to revisit them.

## Review checklist

- Find all version sources in scope.
- Identify duplicate or drifted versions across modules.
- Separate patch, minor, and major changes.
- Call out ecosystem coupling, such as Gradle plus plugin compatibility.
- Prefer the smallest coherent version move that satisfies the request.

## Good targets for automated or low-risk edits

- patch and minor library updates in a version catalog
- replacing duplicated inline versions with existing catalog aliases
- removing duplicate dependency declarations
- aligning repeated plugin versions already intended to match

## Changes that should be surfaced explicitly

- major dependency version updates
- Gradle wrapper version changes
- Kotlin, Android, or other build-platform plugin version changes
- updates that require source or task logic changes to remain compatible

## Verification guidance

- run the narrowest useful build or test task for the changed module
- if plugin or wrapper versions change, verify compatibility concerns separately from dependency resolution
- if no runnable build is available, state that verification was limited to static review