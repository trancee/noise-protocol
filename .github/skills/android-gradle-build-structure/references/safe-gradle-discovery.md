# Safe Gradle Discovery

Use these commands to confirm project structure without intentionally mutating the build.

## Preferred Commands

- `./gradlew projects`
  Lists included projects and subprojects.

- `./gradlew tasks --all`
  Lists available tasks grouped by area.

- `./gradlew help --task <taskName>`
  Explains a specific task when its purpose is unclear.

- `./gradlew properties`
  Useful when you need project-level properties and plugin-applied values.

## Usage Rules

- Run commands from the repository root unless the project clearly requires another working directory.
- Prefer the Gradle wrapper over a system Gradle installation.
- Use these commands only to confirm ambiguous claims after inspecting files first.
- Treat command output as supporting evidence, not a replacement for reading the build definition.

## Avoid By Default

- `publish`, `publishToMavenLocal`, `upload*`
- signing or release-distribution tasks
- deployment tasks
- `clean` as a generic troubleshooting step
- arbitrary custom tasks whose effects are unknown