# Noise Protocol Implementation Plan (Pluggable, Cross-Platform)

## 0. Goals (non-negotiable)

- 100% compliant with Noise Protocol Framework (Rev 34)
- Deterministic, byte-for-byte compatible across platforms
- No protocol shortcuts
- Cryptographic primitives fully swappable
- Constant-time requirements explicitly scoped
- Test-vector-driven correctness
- Clear separation of protocol vs crypto

---

## 0.1 Platform Target Matrix & Pinning Policy

### Android baseline

| Area | Floor / Policy |
|---|---|
| minSdk | 26 (Android 8.0) |
| targetSdk | 35 for initial implementation; bump to latest stable Android API in dedicated version-bump PRs |
| compileSdk | 35 for initial implementation; keep equal to targetSdk |
| Java / Kotlin | Java 17 toolchain, Kotlin 2.x (exact patch pinned) |
| Gradle / AGP | Use exact AGP + Gradle wrapper pair from official compatibility matrix; no `+` or dynamic versions |
| Testing baseline | JUnit 5 + Kotlin test, `kotlinx-coroutines-test`, Robolectric, AndroidX instrumentation runner for device/emulator vector checks |

### iOS baseline

| Area | Floor / Policy |
|---|---|
| Deployment target | iOS 15.0 |
| Swift tools | Swift tools 6.x baseline (`// swift-tools-version` pinned) |
| Xcode | Pin exact stable major.minor in CI; upgrades only in dedicated version-bump PRs after full vector/interoperability pass |
| Testing baseline | Swift Testing for main suites, XCTest interoperability where required, deterministic vector fixtures shared with Android |

### Version pinning process (offline-safe)

1. During scaffolding/release prep, verify latest stable versions from official Android, Gradle, Swift, and Xcode release sources.
2. Pin exact versions in code (single commit/PR):  
   - Android: `android/gradle/wrapper/gradle-wrapper.properties`, `android/gradle/libs.versions.toml`, and build-logic/module Gradle files that set `minSdk`/`targetSdk`/`compileSdk` and JVM toolchain.  
   - iOS: `ios/Package.swift` (`swift-tools-version` + package pins), `ios/Package.resolved`, and Xcode/CI config files that declare deployment target and Xcode version.
3. Keep versions immutable between release bumps (no floating ranges, no branch-based dependency refs).


### Android bootstrap usage (current scaffold)

- Gradle root: `android/settings.gradle.kts` and `android/build.gradle.kts`
- Bootstrap modules: `:noise-core`, `:noise-crypto`, `:noise-testing`
- Build logic is intentionally straightforward for bootstrap (version catalog + module scripts, no convention plugins yet)
- Run baseline tests: `cd android && gradle --no-daemon --console=plain :noise-core:test :noise-crypto:test :noise-testing:test`
- Current Android APIs are compile-safe Kotlin placeholders with no protocol logic yet.

### iOS bootstrap usage (current scaffold)

- Swift package manifest: `ios/Package.swift`
- Bootstrap modules: `NoiseCore`, `NoiseCryptoAdapters`, `NoiseTestHarness`
- Run baseline tests: `cd ios && swift test`
- Current iOS APIs are compile-safe placeholders with Swift 6 language mode, strict concurrency checks, and warnings treated as errors.

### Local verification commands (developer workflow)

- Android module tests: `cd android && gradle --no-daemon --console=plain :noise-core:test :noise-crypto:test :noise-testing:test`
- iOS Swift package tests: `cd ios && swift test`
- Cross-platform deterministic interop check: `./scripts/verify-cross-platform-interop.sh`

### CI validation matrix (current scaffold)

- Workflow: `.github/workflows/ci.yml`
- Android job (`ubuntu-24.04`, Java 17, Gradle 8.10.2): `cd android && gradle --no-daemon --console=plain :noise-core:test :noise-crypto:test :noise-testing:test`
- iOS job (`macos-15`, Xcode 16.1): `cd ios && swift test`
- Cross-platform interop job (`macos-15`, Xcode 16.1, Java 17, Gradle 8.10.2): `./scripts/verify-cross-platform-interop.sh`

### Dependency update policy (Dependabot)

- Config file: `.github/dependabot.yml`
- Weekly update PRs are enabled for `github-actions` (`/`), `gradle` (`/android`), and `swift` (`/ios`).
- Dependabot is limited to patch/minor updates; major version bumps stay manual in dedicated version-bump PRs that must pass the full Android+iOS+interop matrix before merge.

---

## 1. Protocol Scope

### Required handshake

Noise_XX_<DH>_<AEAD>_<HASH>

### Default profile (baseline)

Noise_XX_25519_AESGCM_SHA256

### Supported variations (pluggable)

- DH: 25519, 448  
- AEAD: ChaCha20-Poly1305, AES-GCM  
- Hash: BLAKE2s, SHA-256, SHA-512  

---

## 2. Layered Architecture (MANDATORY)

Application  
Transport Phase  
Handshake Engine  
Symmetric State Machine  
Cryptographic Adapters  

Rule: No layer may depend on a concrete crypto algorithm — only interfaces.

---

## 3. Cryptographic Abstraction Interfaces

### 3.1 Diffie-Hellman (DH)

- keygen() -> (private, public)
- dh(private, public) -> shared_secret
- public_key_length
- private_key_length

Requirements:
- Constant-time
- Zeroize private material
- Fixed output length

---

### 3.2 AEAD

- key_length
- nonce_length
- encrypt(key, nonce, ad, plaintext) -> ciphertext
- decrypt(key, nonce, ad, ciphertext) -> plaintext | error
- rekey(key) -> new_key

Nonce rules:
- 64-bit counter
- Little-endian
- Monotonic
- Overflow = fatal error

---

### 3.3 Hash / HKDF

- hash(data) -> digest
- hmac(key, data) -> mac
- hkdf(chaining_key, ikm, outputs=2) -> (ck, temp_k)
- hash_length
- block_length

Notes:
- BLAKE2s may be implemented in software
- HMAC/HKDF must follow Noise spec exactly

---

## 4. Noise Core State Machines

### 4.1 CipherState

State:
- key?
- nonce (uint64)

Rules:
- Null key = plaintext passthrough
- Nonce increments after every use
- Rekey = encrypt 32 zero bytes with max nonce

---

### 4.2 SymmetricState

State:
- chaining_key
- handshake_hash
- cipher_state

Initialization:
- h = HASH(protocol_name)
- ck = h

Operations:
- mix_hash
- mix_key
- encrypt_and_hash
- decrypt_and_hash
- split

---

### 4.3 HandshakeState

State:
- s, e (local static, ephemeral)
- rs, re (remote static, ephemeral)
- symmetric_state
- message_patterns

Rules:
- Pattern-driven
- No role-based branching outside pattern
- Payload encrypted after pattern tokens

---

## 5. Handshake Pattern Table (XX)

-> e  
<- e, ee, s, es  
-> s, se  

Order is exact.

---

## 6. Transport Phase

- Uses CipherStates from split()
- Separate TX/RX
- Rekey allowed
- No handshake logic here

---

## 7. Serialization Rules

- Raw byte concatenation
- No implicit length prefixes
- Public keys sent verbatim
- Ciphertext includes AEAD tag inline
- No endianness assumptions

---

## 8. Test Vector Strategy

### 8.1 Golden Vectors
- Official Noise vectors
- Handshake messages
- Transcript hash
- Final split keys

### 8.2 Cross-Implementation Harness
- Forced static + ephemeral keys
- Identical payloads
- Byte-for-byte equality

### 8.3 Negative Tests
- MAC failure
- Nonce reuse
- Message reordering
- Corrupted DH input

---

## 9. Performance Constraints

- Zero heap allocation in transport phase
- Preallocated buffers
- No per-message object creation
- Minimal copying

---

## 10. Security Constraints

- Zeroize secrets
- No key logging
- Fail closed
- Constant-time DH
- AEAD misuse resistance

---

## 11. Swap-ability Rules

- Only crypto adapters change
- Protocol code untouched
- Test vectors must still pass

---

## 12. Definition of Done

- All Noise_XX vectors pass
- Cross-platform transcripts identical
- Rekey correctness verified
- Fully pluggable crypto
- No algorithm-specific protocol logic
