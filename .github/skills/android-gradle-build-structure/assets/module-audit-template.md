# Android Gradle Module Audit

## Scope

- Target modules: `<list>`
- DSL style: `<Kotlin DSL|Groovy DSL|mixed>`
- Analysis depth: `module-by-module`

## Root-Level Controls

- Settings and module inclusion: `<where defined>`
- Plugin management: `<where defined>`
- Repository policy: `<where defined>`
- Shared dependency or version policy: `<catalog, constants, convention plugins, none>`

## Module Audit

### `<module>`

- Type: `<app|library|feature|test|other>`
- Build file: `<path>`
- Applied plugins: `<list>`
- Android config: `<namespace, compileSdk, minSdk, targetSdk, signing, build features>`
- Dependencies: `<key external and project dependencies>`
- Variants: `<build types, flavors, notable source sets>`
- Tasks and outputs: `<important tasks and resulting artifacts>`
- Notable conventions or risks: `<duplication, mixed DSL, hidden logic, custom tasks, ambiguity>`

## Cross-Module Relationships

- Dependency graph highlights: `<who depends on whom>`
- Shared conventions: `<plugins, catalogs, common config>`
- Build bottlenecks or complexity points: `<summary>`

## Verification

- Discovery commands used: `<none or safe commands>`
- Unverified assumptions: `<list>`
- Recommended next inspection targets: `<buildSrc, convention plugins, specific modules, version catalog>`