# Gradle Best Practices Reference

This reference condenses the official Gradle best-practices pages into a review checklist and decision guide.

## General

- Prefer Kotlin DSL for new builds and new modules.
- Stay on the latest supported minor release of your current Gradle major version.
- Apply plugins with the `plugins` block.
- Do not rely on plugin application order.
- Do not use internal Gradle APIs.
- Put stable Gradle flags in the root `gradle.properties` file.
- Explicitly set `rootProject.name` in settings.
- Do not place `gradle.properties` files in subprojects.

## Structure

- Split growing codebases into multiple Gradle projects instead of keeping all sources in one project.
- Do not put production source code in the root project.
- Prefer an included `build-logic` composite build over `buildSrc` for shared build logic and convention plugins.
- Use convention plugins to encapsulate repeated build logic.
- Avoid unintentionally creating empty projects when including modules from nested directories.

## Dependencies And Repositories

- Use `gradle/libs.versions.toml` to centralize dependency and plugin versions.
- Name version-catalog aliases consistently and descriptively.
- Declare plugin and dependency repositories in settings.
- When multiple repositories are necessary, add content filtering and be careful with fallback repositories.
- Do not explicitly add Kotlin stdlib unless there is a deliberate version-management reason.
- Avoid duplicate dependency declarations across scopes.
- Without a version catalog, prefer single-string GAV notation over named arguments.
- Apply exclusions as narrowly as possible on the dependency that needs them.

## Tasks And Lazy Configuration

- Use `dependsOn` mainly for lifecycle tasks, not to pass data between producing and consuming tasks.
- Wire producer outputs directly into consumer inputs.
- Prefer `@CacheableTask` or `@DisableCachingByDefault` on task types instead of configuring cache behavior ad hoc per instance.
- Do not call provider `.get()` during configuration when `map` or `flatMap` will do.
- Avoid eager JDK collection APIs on Gradle file collections and configurations during configuration.
- Do not resolve configurations before task execution.
- Use `@PathSensitivity.NONE` for file inputs and `@PathSensitivity.RELATIVE` for directory inputs when path location is not semantically important.
- Give custom tasks a `group` and `description`.
- Avoid overlapping outputs; each task should declare only the files or directories it actually owns.

## Performance

- Prefer the `-bin` Gradle distribution over `-all` unless offline docs and sources are a real requirement.
- Set UTF-8 file encoding explicitly, typically via `org.gradle.jvmargs=-Dfile.encoding=UTF-8`.
- Enable the Build Cache when the build is suitable for it.
- Adopt Configuration Cache deliberately and treat incompatibilities as refactoring targets.
- Move expensive computation, file I/O, network I/O, and other heavy work out of configuration phase and into task actions or lazy providers.

## Security

- Set `distributionSha256Sum` in `gradle-wrapper.properties`.
- Treat wrapper changes as security-sensitive.
- Validate the wrapper JAR and distribution configuration on every Gradle upgrade.
- In GitHub Actions, add wrapper validation with `gradle/actions/wrapper-validation@v3` when CI exists.

## Triage Heuristics

- Fix structure and lazy-configuration problems before tuning micro-optimizations.
- Prefer centralized settings over repeated per-project declarations.
- Prefer typed, cache-friendly task inputs and outputs over manual file handling.
- Prefer small migrations that unblock future improvements over one-shot rewrites.
- If a recommendation conflicts with established project constraints, document the tradeoff instead of forcing compliance.

## Source Material

- <https://docs.gradle.org/current/userguide/best_practices.html>
- <https://docs.gradle.org/current/userguide/best_practices_general.html>
- <https://docs.gradle.org/current/userguide/best_practices_structuring_builds.html>
- <https://docs.gradle.org/current/userguide/best_practices_dependencies.html>
- <https://docs.gradle.org/current/userguide/best_practices_tasks.html>
- <https://docs.gradle.org/current/userguide/best_practices_performance.html>
- <https://docs.gradle.org/current/userguide/best_practices_security.html>