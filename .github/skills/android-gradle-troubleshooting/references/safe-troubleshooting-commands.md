# Safe Troubleshooting Commands

Use these commands to gather evidence without defaulting to destructive or release-oriented actions.

## Preferred Commands

- `./gradlew projects`
  Confirms included projects and module visibility.

- `./gradlew tasks --all`
  Confirms whether expected tasks exist and how they are grouped.

- `./gradlew help --task <taskName>`
  Explains task origin and usage when task ownership is unclear.

- `./gradlew properties`
  Useful for project-level values and some plugin-applied configuration.

- `./gradlew <taskName> --stacktrace`
  Use when a specific failing task must be diagnosed and the user wants command confirmation.

- `./gradlew <taskName> --info`
  Use when more context is needed around dependency or task behavior. Prefer targeted tasks over full builds.

## Usage Rules

- Read the build files first, then use commands to confirm ambiguous claims.
- Prefer the Gradle wrapper over a system Gradle installation.
- Run the smallest relevant task rather than a full build when possible.
- Prefer task-specific investigation over generic retries.

## Avoid By Default

- `clean` as a generic fix
- `build` when a narrower failing task is known
- publish, signing, deployment, or upload tasks
- arbitrary custom tasks whose side effects are unknown
- changing multiple versions at once before isolating the failing compatibility edge