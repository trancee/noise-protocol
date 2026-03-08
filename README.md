# Noise Protocol Library (Android + iOS)

Cross-platform Noise Protocol implementation with native Kotlin and Swift APIs.

[The Noise Protocol Framework](https://noiseprotocol.org/noise.html)
```
Revision: 34
Date: 2018-07-11
```

Tracked upstream baseline:
- `noise-spec.lock`
- Local verification: `bash ./scripts/verify-noise-spec-upstream.sh`
- Scheduled verification: `.github/workflows/noise-spec-watch.yml`
- Maintenance guide: `docs/Noise_Protocol_Upstream_Tracking.md`

Current scope:
- One-way handshake patterns: `N`, `K`, `X`
- Fundamental interactive handshake patterns: `NN`, `NK`, `NX`, `XN`, `XK`, `XX`, `KN`, `KK`, `KX`, `IN`, `IK`, `IX`
- PSK modifiers derived from the protocol name for the current core pattern set, with caller-supplied `pskN` material
- Protocol-name parsing currently accepts only plain base patterns plus optional `pskN` modifiers; unsupported modifiers such as `fallback` remain rejected until implemented
- Core state machines: `CipherState`, `SymmetricState`, `HandshakeState`
- Pluggable crypto adapters
- Shared test-vector harness and Android/iOS interop checks for the current shared vector subset: `NN`, `NK`, `KK`, `IK`, `XX`

## Repository layout

- `android/`: Kotlin/JVM + Android library modules
  - `:noise-core`
  - `:noise-crypto`
  - `:noise-testing`
  - `:noise-protocol` (publishable Android AAR module; Maven artifact `noise-protocol`)
  - source/test package directories follow `noise/protocol/...`
- `Package.swift`: canonical Swift Package entrypoint for repository/tag-based consumption
- `ios/`: Swift sources/tests (with compatibility `ios/Package.swift` manifest)
  - `NoiseCore`
  - `NoiseCryptoAdapters`
  - `NoiseTestHarness`
- `test-vectors/`: shared schema and fixtures
  - `fixtures/v1/` contains the full base handshake/suite coverage matrix (80 vectors) plus representative PSK fixtures (82 vectors total):
    `NN|NK|KK|IK|XX` × `25519|448` × `ChaChaPoly|AESGCM` × `SHA256|SHA512|BLAKE2s|BLAKE2b`
  - Android and iOS both now support direct conversion of representative official Noise wiki vectors into the shared v1 contract. Android imports and persists directly translatable cases; iOS persists directly translatable built-in `25519` and `448` cases. Fallback, hybrid, and asymmetric-prologue cases still require a future schema revision.

Official wiki vectors can be converted into shared v1 fixtures from the Android module with:

```bash
cd android && gradle --no-daemon :noise-testing:convertOfficialNoiseVectors \
  -PofficialNoiseInput=/absolute/path/to/official-vectors.json \
  -PofficialNoiseOutput=/absolute/path/to/output-directory
```

Optional:
- `-PofficialNoiseSchema=../../schema/noise-vector-v1.schema.json`

Repository wrapper:

```bash
bash ./scripts/convert-official-noise-vectors.sh \
  ./scripts/testdata/official-noise-nn-vector.json \
  /absolute/path/to/output-directory
```

The wrapper resolves repo-relative input and output paths before invoking Gradle.

iOS wrapper:

```bash
bash ./scripts/convert-official-noise-vectors-ios.sh \
  ./scripts/testdata/official-noise-nn-vector.json \
  /absolute/path/to/output-directory
```

The iOS wrapper resolves repo-relative input and output paths before invoking `swift run NoiseVectorConverterCLI`, and representative official `448` and `BLAKE2s` inputs now convert successfully through the built-in adapter path.

Cross-platform parity check for converted official vectors:

```bash
bash ./scripts/verify-official-vector-conversion-parity.sh
```

The repository ships representative official-format samples for `NN`, `NN 448`, `NN BLAKE2s`, `NNpsk0`, and `XXpsk2` under `scripts/testdata/`, and the parity script checks Android/iOS shared-fixture output for all five.

## GitHub releases

- Workflow: `.github/workflows/release.yml`
- Full operator runbook: `RELEASE.md`
- Canonical version contract:
  - `VERSION` is the single source of truth for Android, iOS, and release automation.
  - Release tags must match `v<VERSION>` and are validated by:
    - `bash ./scripts/verify-version-parity.sh` (CI)
    - `bash ./scripts/verify-version-parity.sh <tag>` (release)
- Trigger:
  - push a tag matching `v*` (for example `v0.1.0`)
  - manual dispatch with a `tag` input
- Publish targets:
  - Maven Central artifacts:
    - `ch.trancee:noise-protocol:<VERSION>`
    - Task: `:noise-protocol:publishAndReleaseToMavenCentral`
    - Required secrets: `MAVEN_CENTRAL_USERNAME`, `MAVEN_CENTRAL_PASSWORD`, `MAVEN_SIGNING_KEY`, `MAVEN_SIGNING_PASSWORD`
- Published GitHub release assets:
  - `noise-protocol-<tag>.tar.gz` (Android `noise-core`, `noise-crypto`, `noise-testing` JARs)
  - `noise-protocol-<tag>.aar` (Android AAR artifact for direct consumption)
  - `noise-ios-swiftpm-<tag>.tar.gz` (Swift Package manifest + Sources + `VERSION`)
  - `SHA256SUMS.txt`

## Versioning policy

- The library follows SemVer from `VERSION` for Android artifacts, Swift Package tags, and release automation.
- The upstream Noise specification baseline is versioned separately in `noise-spec.lock` and verified in CI, release preflight, and the weekly Noise Spec Watch workflow.
- A routine upstream re-check that does not change `noise-spec.lock` does not require a library version bump.
- If an upstream Noise change requires repository changes, choose the release bump by impact: patch for docs/test/automation-only work, minor for additive compatible behavior, major for breaking API or interoperability changes.
- Detailed maintenance guidance lives in `docs/Noise_Protocol_Upstream_Tracking.md`.

## Developer guide

### Start with the default unless you need a reason not to

The default bootstrap profile on both platforms is:

- Protocol name: `Noise_XX_25519_AESGCM_SHA256`
- Pattern: `XX`
- DH: `25519`
- AEAD: `AESGCM`
- Hash/HKDF: `SHA256`

Use that default when:

- both peers can exchange static keys during the handshake
- you want a well-supported interactive handshake with identity protection during setup
- you do not need a pre-shared key modifier

Move away from the default only when your deployment model requires it.

### Choose the right variation

Common protocol-name variations and when to use them:

| Need | Recommended variation | Why |
|---|---|---|
| No static keys known in advance | `Noise_NN_...` | simplest anonymous interactive handshake |
| Responder static key pinned in advance | `Noise_NK_...` or `Noise_IK_...` | avoids sending or trusting an unauthenticated responder static late in the flow |
| Mutual static authentication during handshake | `Noise_KK_...` or `Noise_XX_...` | both peers authenticate with static keys |
| One-way request pattern | `Noise_N_...`, `Noise_K_...`, or `Noise_X_...` | supported by the core without a full interactive handshake |
| Pre-shared key hardening | add `pskN`, for example `Noise_XXpsk2_25519_ChaChaPoly_SHA256` | mixes an out-of-band PSK into the transcript at message `N` |
| Larger DH security margin | replace `25519` with `448` | available on both platforms |
| Prefer software-friendly AEAD | replace `AESGCM` with `ChaChaPoly` | good fit on devices without strong AES acceleration |
| Stronger or alternative hash/HKDF | replace `SHA256` with `SHA512`, `BLAKE2s`, or `BLAKE2b` | match ecosystem or policy requirements |

Protocol-name rules:

- Both peers must use the exact same protocol name.
- The protocol name must match the selected handshake pattern and crypto suite exactly.
- Only base patterns plus optional `pskN` modifiers are supported today.
- Unsupported modifiers such as `fallback` are rejected.

### Best practices

- Prefer `HandshakeSession` on Android and `NoiseHandshakeSession` on Swift for application code. Drop down to `HandshakeState` only when you need lower-level control.
- Generate fresh ephemeral keys per handshake. Reuse static keys only when your trust model requires long-term identities.
- Provide `remoteStatic` only when the chosen pattern and your trust model actually require a pinned remote identity.
- Use `expectedDirection()` and `isComplete()` to enforce turn-taking instead of inferring message order in app code.
- Use `handshakeHash()` for channel binding only after both peers agree on the handshake state you are binding.
- Keep PSKs outside the repository and inject them by placement index, for example `psk0` -> `0`, `psk2` -> `2`.
- Treat `setNonce(...)` and `setNonce(_:)` as advanced transport controls for out-of-order delivery. Do not use them in ordinary ordered transports.
- Use the framed message helpers only for Noise handshake framing. They enforce the shared 16-bit big-endian frame format and reject messages larger than 65,535 bytes.
- Prefer a single cached fixture repository when running repeated deterministic tests or negative cases.

## Android usage (Kotlin)

Minimum supported Android API level: 23.

### 1) Add dependency

Published Android artifacts are uploaded by release workflow to Maven Central as a single coordinate. `ch.trancee:noise-protocol` bundles `noise-core` and `noise-crypto` classes directly in the AAR.

Example (`build.gradle.kts` in your app project):

```kotlin
repositories {
    mavenCentral()
}

dependencies {
    implementation("ch.trancee:noise-protocol:<VERSION>")
}
```

For local source development, include this repository build:

```kotlin
includeBuild("../noise-protocol/android")
```

### 2) Build the default Noise configuration

```kotlin
import noise.protocol.crypto.CryptoProvider

val provider = CryptoProvider()
val defaultConfig = provider.createDefaultConfiguration()
val suite = defaultConfig.suite
// defaultConfig.pattern == HandshakePattern.XX
// defaultConfig.protocolName == "Noise_XX_25519_AESGCM_SHA256"
```

If you are building application code instead of a test harness, prefer `HandshakeSession` as the main entry point and keep the provider/configuration objects long-lived when possible.

### 3) Run a handshake (default XX profile)

```kotlin
import noise.protocol.core.HandshakeRole
import noise.protocol.core.HandshakeState

val initiatorStatic = suite.diffieHellman.generateKeyPair()
val responderStatic = suite.diffieHellman.generateKeyPair()

val initiator = HandshakeState.initialize(
    pattern = defaultConfig.pattern,
    role = HandshakeRole.INITIATOR,
    cryptoSuite = suite,
    protocolName = defaultConfig.protocolName,
    localStatic = initiatorStatic,
    remoteStatic = responderStatic.publicKey
)
val responder = HandshakeState.initialize(
    pattern = defaultConfig.pattern,
    role = HandshakeRole.RESPONDER,
    cryptoSuite = suite,
    protocolName = defaultConfig.protocolName,
    localStatic = responderStatic,
    remoteStatic = initiatorStatic.publicKey
)

val m1 = initiator.writeMessage("hello".encodeToByteArray())
responder.readMessage(m1)

val m2 = responder.writeMessage("world".encodeToByteArray())
initiator.readMessage(m2)

val m3 = initiator.writeMessage("done".encodeToByteArray())
responder.readMessage(m3)

check(initiator.isComplete() && responder.isComplete())

val (tx, rx) = initiator.splitTransportStates()

val frame = m3.encoded()
val decoded = HandshakeMessage.decode(
  direction = MessageDirection.INITIATOR_TO_RESPONDER,
  expectedTokens = m3.tokenValues.map { it.token },
  encoded = frame
)
```

`HandshakeMessage.encoded()` uses a 16-bit big-endian frame layout and rejects messages larger than 65,535 bytes, matching the Noise framework guidance for application-level framing.
After each handshake step, `initiator.handshakeHash()` exposes the current transcript hash for channel binding, and `CipherState.setNonce(...)` can be used for monotonic nonce overrides in out-of-order transport integrations.

For a higher-level stateful API that mirrors the Swift package surface more closely, use `HandshakeSession`:

```kotlin
val initiatorSession = HandshakeSession()
initiatorSession.initialize(
  pattern = defaultConfig.pattern,
  role = HandshakeRole.INITIATOR,
  cryptoSuite = suite,
  protocolName = defaultConfig.protocolName,
  localStatic = initiatorStatic,
  remoteStatic = responderStatic.publicKey
)

val responderSession = HandshakeSession()
responderSession.initialize(
  pattern = defaultConfig.pattern,
  role = HandshakeRole.RESPONDER,
  cryptoSuite = suite,
  protocolName = defaultConfig.protocolName,
  localStatic = responderStatic,
  remoteStatic = initiatorStatic.publicKey
)

val outbound = initiatorSession.writeMessage("hello".encodeToByteArray())
val inboundPayload = responderSession.readMessage(outbound)
check(inboundPayload.contentEquals("hello".encodeToByteArray()))
check(initiatorSession.expectedDirection() == MessageDirection.RESPONDER_TO_INITIATOR)
```

Use the session wrapper when:

- you want framed `ByteArray` messages directly
- you need `expectedDirection()` / `isComplete()` progress inspection
- you want a surface that mirrors the Swift API closely

### 4) Use a different crypto suite

```kotlin
import noise.protocol.core.HandshakePattern
import noise.protocol.crypto.NoiseAeadAlgorithm
import noise.protocol.crypto.NoiseCryptoAlgorithms
import noise.protocol.crypto.NoiseDhAlgorithm
import noise.protocol.crypto.NoiseHashAlgorithm

val customAlgorithms = NoiseCryptoAlgorithms(
    dh = NoiseDhAlgorithm.X25519,
    aead = NoiseAeadAlgorithm.CHACHA20_POLY1305,
    hash = NoiseHashAlgorithm.SHA512
)
val customSuite = provider.createSuite(customAlgorithms)
val customPattern = HandshakePattern.XX
val customProtocolName = "Noise_XX_25519_ChaChaPoly_SHA512"
```

Use `customSuite`, `customPattern`, and `customProtocolName` in `HandshakeState.initialize(...)` on both peers.
`CryptoProvider.createSuite(...)` is cheap to call repeatedly because stateless adapter instances are reused internally.

Built-in Android suite variations:

- DH: `NoiseDhAlgorithm.X25519`, `NoiseDhAlgorithm.X448`
- AEAD: `NoiseAeadAlgorithm.AES_GCM`, `NoiseAeadAlgorithm.CHACHA20_POLY1305`
- Hash/HKDF: `NoiseHashAlgorithm.SHA256`, `NoiseHashAlgorithm.SHA512`, `NoiseHashAlgorithm.BLAKE2S`, `NoiseHashAlgorithm.BLAKE2B`

### 4.1) Add a PSK modifier

If the protocol name contains `pskN`, both peers must supply a PSK at placement `N`.

```kotlin
val pskProtocolName = "Noise_XXpsk2_25519_ChaChaPoly_SHA256"
val pskPattern = HandshakePattern.XX
val pskBytes = ByteArray(32) { it.toByte() }

val initiatorSession = HandshakeSession()
initiatorSession.initialize(
  pattern = pskPattern,
  role = HandshakeRole.INITIATOR,
  cryptoSuite = suite,
  protocolName = pskProtocolName,
  preSharedKeys = mapOf(2 to pskBytes),
  localStatic = initiatorStatic,
  remoteStatic = responderStatic.publicKey
)
```

Best practice:

- keep the PSK map minimal and exact
- do not pass unexpected PSK placements
- rotate PSKs independently from static key pairs

### 5) Reuse the shared vector harness efficiently

When running repeated deterministic checks against the shared repository fixtures, prefer the cached repository API from
`noise-testing` so the JSON corpus is parsed once and then reused by `vector_id`.

```kotlin
import noise.protocol.testing.NoiseTestHarness

val harness = NoiseTestHarness(provider)
val fixtures = harness.loadFixtureRepository(Path.of("../test-vectors/fixtures/v1"))

val deterministic = harness.runDeterministic(fixtures, "noise-nn-placeholder")
val negative = harness.runNegativeCase(fixtures, "noise-nn-placeholder", "flip-tag-msg1")
check(deterministic.passed)
check(!negative.passed)
```

## iOS usage (Swift)

Requires Swift 6.1 or newer.

### 1) Add package

Add this repository as a Swift Package dependency and link:
- `NoiseCore`
- `NoiseCryptoAdapters`

Example (`Package.swift`):
- Add `.package(path: "../noise-protocol")` for local development, or the repository URL for tag-based usage.
- In your target dependencies, link the package products:
  - `NoiseCore`
  - `NoiseCryptoAdapters`

If you need the deterministic fixture harness or official-vector conversion support in Swift tools or tests, also link `NoiseTestHarness`.

### 2) Build the default Noise configuration

```swift
import Foundation
import NoiseCore
import NoiseCryptoAdapters

let factory = NoiseCryptoAdapterFactory()
let suite = NoiseCryptoSuiteDescriptor.bootstrapDefault
let provider = try await factory.makeBootstrapDefaultProvider()
```

For app code, prefer keeping one `NoiseCryptoAdapterFactory` around and creating providers from descriptors as needed. The built-in registry is shared internally, so repeated provider construction is cheap.

### 3) Run a handshake session (default XX profile)

```swift
import Foundation
import NoiseCore

let initiatorSession = NoiseHandshakeSession()
let responderSession = NoiseHandshakeSession()
let initiatorStatic = try provider.diffieHellman.generateKeyPair()
let responderStatic = try provider.diffieHellman.generateKeyPair()

let initiatorConfig = NoiseHandshakeConfiguration(
    protocolName: suite.protocolName,
    isInitiator: true,
    handshakePattern: .xx,
    localStaticKey: initiatorStatic,
    remoteStaticKey: responderStatic.publicKey
)
let responderConfig = NoiseHandshakeConfiguration(
    protocolName: suite.protocolName,
    isInitiator: false,
    handshakePattern: .xx,
    localStaticKey: responderStatic,
    remoteStaticKey: initiatorStatic.publicKey
)

try await initiatorSession.initialize(with: initiatorConfig, cryptoProvider: provider)
try await responderSession.initialize(with: responderConfig, cryptoProvider: provider)

let m1 = try await initiatorSession.writeMessage(payload: Data("hello".utf8))
_ = try await responderSession.readMessage(m1)

let m2 = try await responderSession.writeMessage(payload: Data("world".utf8))
_ = try await initiatorSession.readMessage(m2)

let m3 = try await initiatorSession.writeMessage(payload: Data("done".utf8))
_ = try await responderSession.readMessage(m3)

let transport = try await initiatorSession.splitTransportStates()
let channelBinding = try await initiatorSession.handshakeHash()
let complete = try await initiatorSession.isComplete()
```

Swift `NoiseHandshakeMessage.encoded()` uses the same 16-bit big-endian frame layout and enforces the same 65,535-byte maximum frame size.
For out-of-order transport use cases, `NoiseCipherState.setNonce(_:)` allows monotonic nonce advancement without resetting keys.
`NoiseHandshakeSession.expectedDirection()` and `isComplete()` expose handshake progress to callers that need to drive strict turn-taking explicitly.

Use `NoiseHandshakeSession` as the default app-facing API. Use lower-level state types only when you need custom message orchestration or direct state-machine testing.

### 4) Use a different crypto suite

```swift
import NoiseCore
import NoiseCryptoAdapters

let customSuite = NoiseCryptoSuiteDescriptor(
    protocolName: NoiseProtocolDescriptor(rawValue: "Noise_XX_25519_ChaChaPoly_SHA512"),
    diffieHellman: "25519",
    cipher: "ChaChaPoly",
    hash: "SHA512"
)
let customProvider = try await factory.makeProvider(for: customSuite)
```

Use `customSuite.protocolName` and `customProvider` when initializing both handshake sessions.
Default `NoiseCryptoAdapterFactory()` instances share a built-in registry actor, so repeated factory construction does not rebuild the built-in adapter catalog.

Built-in Swift suite variations:

- DH: `25519`, `448`
- Ciphers: `ChaChaPoly`, `AESGCM`
- Hash/HKDF: `SHA256`, `SHA512`, `BLAKE2s`, `BLAKE2b`

### 4.1) Add a PSK modifier

If the protocol name contains `pskN`, both peers must supply a PSK at placement `N`.

```swift
let pskSuite = NoiseCryptoSuiteDescriptor(
  protocolName: NoiseProtocolDescriptor(rawValue: "Noise_XXpsk2_25519_ChaChaPoly_SHA256"),
  diffieHellman: "25519",
  cipher: "ChaChaPoly",
  hash: "SHA256"
)
let pskProvider = try await factory.makeProvider(for: pskSuite)
let psk = Data((0..<32).map(UInt8.init))

let initiatorConfig = NoiseHandshakeConfiguration(
  protocolName: pskSuite.protocolName,
  isInitiator: true,
  handshakePattern: .xx,
  preSharedKeys: [2: psk],
  localStaticKey: initiatorStatic,
  remoteStaticKey: responderStatic.publicKey
)
```

Best practice:

- use integer PSK placements that match the protocol name exactly
- inject the same PSK set on both peers
- keep PSKs separate from the static identity-key lifecycle

### 5) Reuse the shared iOS vector harness efficiently

When running repeated deterministic or negative-case checks from Swift, prefer the cached repository actor in
`NoiseTestHarness` so the shared fixture corpus is decoded once and then reused by `vector_id`.

```swift
import NoiseTestHarness

let repository = NoiseVectorFixtureRepository()
let runner = NoiseVectorRunner()

let deterministic = try await runner.verifyExpected(repository: repository, vectorID: "noise-nn-placeholder")
let negative = try await runner.verifyNegativeCase(
  repository: repository,
  vectorID: "noise-nn-placeholder",
  caseID: "flip-tag-msg1"
)
```

## Verify locally

```bash
# Noise spec parser regression check
bash ./scripts/test-verify-noise-spec-upstream.sh

# Upstream Noise spec baseline
bash ./scripts/verify-noise-spec-upstream.sh

# Version contract parity
bash ./scripts/verify-version-parity.sh

# Android
cd android
gradle --no-daemon --console=plain :noise-core:test :noise-crypto:test :noise-testing:test
gradle --no-daemon --console=plain :noise-protocol:assembleRelease :noise-protocol:publishToMavenLocal
cd ..

# iOS (repository-root Swift Package entrypoint)
swift test

# Cross-platform interop
bash ./scripts/verify-cross-platform-interop.sh
```

## Run benchmark-oriented tests

```bash
# Run all benchmark-oriented variations and refresh benchmark results doc
bash ./scripts/run-benchmarks-and-update-doc.sh
```

Policy: always use the script above when running benchmarks so `docs/Benchmark_Test_Results.md` stays current.

## Notes and current limitations

- Android built-in provider supports:
  - DH: `X25519`, `X448`
  - AEAD: `ChaCha20-Poly1305`, `AES-GCM`
  - Hash/HKDF: `SHA-256`, `SHA-512`, `BLAKE2s`, `BLAKE2b`
- iOS built-in registry ships:
  - DH: `25519`, `448`
  - Ciphers: `ChaChaPoly`, `AESGCM`
  - Hashes: `SHA256`, `SHA512`, `BLAKE2s`, `BLAKE2b`
- Official-vector conversion currently supports directly translatable shared-v1 cases. Fallback, hybrid, and asymmetric-prologue official wiki vectors still need a future schema revision.
- The shared repository fixture corpus currently focuses interop coverage on `NN`, `NK`, `KK`, `IK`, and `XX`, even though the core protocol surface supports the broader one-way and interactive pattern set listed above.

For architecture and internals, see:
- `docs/Noise_Protocol_Core.md`
- `docs/Noise_Crypto_Adapters.md`
- `docs/Noise_Test_Harness.md`
