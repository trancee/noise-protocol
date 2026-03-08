# Gradle Build Overview Reference

This reference captures the parts of the Android Gradle build overview most useful when explaining a project's build structure.

## Core Concepts

- A build system transforms source code into an executable application or library.
- Gradle organizes build work as tasks.
- Plugins register tasks and configure how tasks connect through inputs and outputs.
- Build files should stay declarative where possible. Reusable logic belongs in plugins rather than ad hoc build-script code.

## Build Phases

Gradle runs in three phases:

1. Initialization
   Determines which projects are included in the build and sets up plugin and dependency resolution.

2. Configuration
   Evaluates build files, applies plugins, and registers tasks. Configuration code cannot rely on outputs that only exist during execution.

3. Execution
   Runs the requested tasks in dependency order based on the task graph. Up-to-date tasks may be skipped.

## DSL Notes

- Gradle supports Kotlin DSL and Groovy DSL.
- Android guidance recommends Kotlin DSL when possible.
- The DSL is declarative: build files describe what to build, while plugins define how it is built.

## Dependencies

- Repositories provide published artifacts and metadata.
- External dependencies are typically declared as `group:artifact:version`.
- Android projects may also depend on subprojects or modules within the same repo.
- Modularization can reduce rebuild scope and separate responsibilities.

## Variants

- Build variants are composed from build types and product flavors.
- Common build types include `debug` and `release`.
- Debug builds are debuggable and easier to inspect.
- Release builds are optimized, signed for distribution, and more restricted.
- If flavors exist, Android Gradle Plugin creates a variant for each flavor and build type combination, for example `demoDebug` or `fullRelease`.

## Outputs to Expect

- Application modules usually produce APKs or AABs.
- Library modules usually produce AARs.
- Testing and analysis tasks may also produce reports and generated sources.