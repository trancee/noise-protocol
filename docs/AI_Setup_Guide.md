# AI Setup Guide: Open-Source Android (Kotlin) + iOS (Swift) Library

## Purpose
This document instructs an AI agent how to **design, structure, build, publish, and document** an open-source library targeting **Android (Kotlin)** and **iOS (Swift)**.

The goal is to produce **ecosystem-native artifacts** that meet modern developer expectations:
- Android → AAR published to Maven repositories
- iOS → Swift Package (source-first), optionally binary XCFramework
- Clear, unified developer documentation
- Consistent versioning and release automation

This guide assumes the library is:
- Open source
- Publicly distributed
- Intended for broad developer adoption

---

## Target Artifacts (Authoritative)

### Android
- Primary artifact: **AAR**
- Published to: **Maven-compatible repository** (preferably Maven Central)
- Supplementary artifacts:
  - Sources JAR
  - Javadoc / Dokka JAR

### iOS
- Primary artifact: **Swift Package (source-based)**
- Distributed via Git repository tags
- Optional secondary artifact:
  - **XCFramework** (only if binary distribution is required)

### Versioning
- Semantic Versioning (SemVer)
- Version parity across platforms
- One Git tag corresponds to one Android + iOS release

---

## Repository Structure (Recommended)

```
repo/
├── android/
│   └── library/
│       ├── build.gradle.kts
│       └── src/
├── ios/
│   └── Sources/
│       └── LibraryName/
├── Package.swift
├── README.md
├── CHANGELOG.md
├── LICENSE
└── .github/workflows/
```

Notes:
- Android and iOS code are isolated
- A single root README covers both platforms
- Package.swift lives at the repository root

---

## Android Setup Instructions

### Project Configuration
- Use Gradle with Kotlin DSL
- Configure the module as an Android Library
- Target stable Android SDK versions

### Build Outputs
The AI must configure the build to produce:
- AAR
- Sources JAR
- Javadoc or Dokka JAR

### Publishing
The AI must:
1. Configure Maven publishing
2. Sign artifacts
3. Publish to a Maven repository

Publishing expectations:
- Group ID is owned by the organization
- Artifact ID matches the library name
- Version follows SemVer

### Android API Expectations
- Kotlin-first public API
- Avoid leaking internal types
- Include consumer ProGuard rules
- Minimize transitive dependencies

---

## iOS Setup Instructions

### Swift Package (Primary)
The AI must:
- Create a Package.swift file
- Use source-based targets
- Define minimum supported iOS version
- Expose a clean public module

### API Design
- Swift-native naming conventions
- Avoid Obj-C compatibility unless required
- Use access control intentionally (public vs internal)

### Optional Binary Distribution
Only if required:
- Build an XCFramework
- Ensure simulator + device support
- Optionally expose as a binary target in the Swift package

---

## Versioning & Releases

### Rules
- One version number for Android and iOS
- One Git tag per release
- No platform-specific version drift

### Changelog
The AI must maintain:
- CHANGELOG.md
- Human-readable entries
- Clear indication of breaking changes

---

## Developer Documentation (Required)

### README.md (Mandatory)
The AI must generate a README that includes:

1. Project overview
2. Installation instructions
   - Android (Gradle)
   - iOS (Swift Package)
3. Minimal usage example for each platform
4. Versioning policy
5. License

### API Documentation
- Android: Dokka-generated docs
- iOS: Swift doc comments

Documentation must:
- Focus on public APIs
- Avoid internal implementation details
- Include examples where non-obvious

---

## CI / Automation Expectations

The AI should assume CI is available and:
- Build Android artifacts on each release
- Validate Swift Package builds
- Publish artifacts on Git tag
- Fail on version mismatch between platforms

---

## Design Principles to Enforce

- Platform-native developer experience
- Minimal configuration for consumers
- Explicit public API boundaries
- Stability over cleverness
- Documentation treated as a first-class artifact

---

## Summary (Non-Negotiable Defaults)

- Android artifact: AAR published to Maven
- iOS artifact: Swift Package (source)
- Unified versioning
- Clear README and examples
- Automated releases

This document is the authoritative instruction set for any AI responsible for setting up, building, publishing, or documenting this library.

