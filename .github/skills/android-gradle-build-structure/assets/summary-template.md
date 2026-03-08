# Android Gradle Build Structure Summary

## Project Shape

- Build style: `<single-module|multi-module>`
- Settings file: `<settings.gradle|settings.gradle.kts|not found>`
- Included modules: `<list>`

## Root Build Configuration

- Root DSL: `<Kotlin DSL|Groovy DSL>`
- Plugin management: `<where it is declared>`
- Dependency repositories: `<where they are declared>`
- Shared conventions: `<buildSrc, convention plugins, version catalog, or none>`

## Module Summary

- `<module>`: `<app|library|feature|test|other>`; plugins: `<list>`; purpose: `<short description>`

## Repositories And Dependencies

- External dependencies: `<how they are managed>`
- Project dependencies: `<module relationships>`
- Version management: `<version catalog, constants, inline versions, unknown>`

## Variants And Source Sets

- Build types: `<list>`
- Product flavors: `<list or none>`
- Variant pattern: `<for example demoDebug/fullRelease or build-type-only>`
- Source sets: `<main plus notable overrides>`

## Key Tasks And Outputs

- Discovery commands used: `<none|./gradlew projects|./gradlew tasks --all|other safe commands>`
- Main tasks: `<assemble, bundle, test, lint, publish, custom tasks>`
- Expected outputs: `<APK, AAB, AAR, reports, generated sources>`

## Open Questions Or Ambiguities

- `<unknown, inferred, or conflicting configuration details>`