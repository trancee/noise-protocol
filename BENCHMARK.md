# Benchmark Results

Performance benchmarks for all 8 cipher suites across all handshake patterns and transport operations. Results collected on Apple M1 (macOS 14, ARM64) — iOS benchmarks use CryptoKit (Swift), Android benchmarks use JCA/JCE (Kotlin/JVM 21).

> **Note:** These are micro-benchmarks on development hardware. Real-world performance varies by device, OS version, and system load. BLAKE2 suites use a pure-Swift/pure-Kotlin implementation ([blake-hash](https://github.com/trancee/blake-hash)) and are significantly slower than SHA-based suites which use hardware-accelerated platform APIs.

## Quick Summary

| Metric | ChaChaPoly + SHA-256 | AES-GCM + SHA-256 |
|--------|---------------------|--------------------|
| NN handshake (2 msgs) | ~130 µs (iOS) / ~345 µs (JVM) | ~125 µs (iOS) / ~280 µs (JVM) |
| XX handshake (3 msgs) | ~270 µs (iOS) / ~590 µs (JVM) | ~260 µs (iOS) / ~540 µs (JVM) |
| IK handshake (2 msgs) | ~320 µs (iOS) / ~665 µs (JVM) | ~310 µs (iOS) / ~650 µs (JVM) |
| Transport encrypt 1 KB | 3.3 µs (iOS) / 2.3 µs (JVM) | 2.2 µs (iOS) / 0.6 µs (JVM) |
| Transport throughput | ~280 MB/s (iOS) / ~210 MB/s (JVM) | ~430 MB/s (iOS) / ~727 MB/s (JVM) |

## Performance Optimizations

The codebase was profiled and optimized across both platforms. Key changes and their impact:

### Optimizations Applied

| Optimization | Platform | Impact |
|---|---|---|
| **Cache DH public key** — stored computed public key instead of recalculating on every access | Both | Handshake: 20–30% faster (iOS), ~2% faster (Android) |
| **HKDF counter constants** — pre-allocated `[0x01]`, `[0x02]`, `[0x03]` as static constants | Both | Eliminates per-call allocations in every MixKey/Split |
| **BLAKE2 HMAC loop optimization** — replaced `map` closure with explicit for-loop for ipad/opad XOR | Both | Reduces closure overhead in BLAKE2 suites |
| **Pre-sized handshake buffer** — `Data(capacity: 256)` (iOS), `ByteArrayOutputStream(256)` (Android) | Both | Eliminates buffer regrowth during writeMessage |
| **ThreadLocal JCA provider caching** — reuse `Cipher`, `MessageDigest`, `Mac`, `KeyPairGenerator`, `KeyFactory`, and `KeyAgreement` instances via `ThreadLocal` | Android | Handshake: **6–10% faster**; Transport: **2–3× faster** for AES-GCM |
| **HKDF concatenation** — `System.arraycopy` instead of `+` operator for output+counter | Android | Avoids intermediate ByteArray allocation |

### Before/After: iOS Handshake

| Pattern | Before (µs) | After (µs) | Improvement |
|---------|------------:|-----------:|------------:|
| N (1 msg)  | 126 | 101 | **20%** |
| NN (2 msg) | 179 | 129 | **28%** |
| NK (2 msg) | 238 | 192 | **19%** |
| XX (3 msg) | 358 | 272 | **24%** |
| IK (2 msg) | 389 | 320 | **18%** |
| KK (2 msg) | 359 | 304 | **15%** |
| NKpsk0 (2 msg) | 329 | 232 | **29%** |
| IKpsk2 (2 msg) | 477 | 354 | **26%** |

> Average handshake improvement on iOS: **~22%** (ChaChaPoly\_SHA256 suite).

### Before/After: Android Transport

| Suite | Before (MB/s) | After (MB/s) | Improvement |
|-------|-------------:|------------:|------------:|
| ChaChaPoly\_SHA256 | 197 | 211 | +7% |
| ChaChaPoly\_BLAKE2s | 326 | 390 | **+20%** |
| ChaChaPoly\_BLAKE2b | 322 | 385 | **+20%** |
| AESGCM\_SHA256 | 348 | 727 | **+109%** |
| AESGCM\_SHA512 | 365 | 1,037 | **+184%** |
| AESGCM\_BLAKE2s | 377 | 1,055 | **+180%** |
| AESGCM\_BLAKE2b | 381 | 1,056 | **+177%** |

### Before/After: Android Handshake

| Pattern | Before (µs) | After (µs) | Improvement |
|---------|------------:|-----------:|------------:|
| NN (2 msg) | 382 | 345 | **10%** |
| NK (2 msg) | 526 | 495 | **6%** |
| XX (3 msg) | 605 | 590 | **3%** |
| IK (2 msg) | 706 | 666 | **6%** |
| KK (2 msg) | 729 | 687 | **6%** |

> The AES-GCM transport gains come from `ThreadLocal` caching of JCA `Cipher` instances. Handshake improvements come from caching `KeyPairGenerator`, `KeyFactory`, `KeyAgreement`, `MessageDigest`, and `Mac` instances — eliminating ~35 JCA provider lookups per handshake.

## Why Android Handshakes Are Slower Than iOS

iOS handshakes are **2–3× faster** than Android/JVM for the same patterns. This is a fundamental platform difference, not a code quality issue:

| Factor | iOS (CryptoKit) | Android (JCA) | Impact |
|--------|-----------------|---------------|--------|
| **X25519 DH** | Native ARM assembly via Secure Enclave coprocessor | Java implementation via JCA provider | **~2× slower** — dominates handshake time |
| **Key construction** | Direct `Curve25519.KeyAgreement.PublicKey(rawRepresentation:)` | `BigInteger` conversion → `XECPublicKeySpec` → `KeyFactory.generatePublic()` | **~1.5× overhead** per DH call |
| **Hash/HMAC** | Hardware-accelerated `SHA256` / `HMAC<SHA256>` | JIT-compiled `MessageDigest` / `Mac` | **~1.5× slower** |
| **Object model** | Value types (`Data`, `SymmetricKey`) — stack-allocated | Heap objects (`ByteArray`, `SecretKeySpec`) — GC pressure | Adds latency variance |

The X25519 scalar multiplication alone accounts for ~70% of handshake time on both platforms. CryptoKit's implementation benefits from Apple's hardware-accelerated cryptographic coprocessor, while JCA uses a software implementation that, even with JIT optimization, cannot match native speed.

**Transport throughput tells a different story**: Android AES-GCM (727–1,056 MB/s) significantly outperforms iOS (425–430 MB/s) because the JVM's AES-NI intrinsics are highly optimized after JIT warmup, and our `ThreadLocal<Cipher>` caching eliminates provider lookup overhead.

## Methodology

- **Handshake:** Full initiator↔responder handshake with key generation outside the timed section. 5 warmup iterations + 20 measured iterations. Reports average, min, and max.
- **Transport:** After completing an NN handshake, encrypt and decrypt a 1 KB payload. 100 warmup + 1000 measured iterations. Reports per-operation time and aggregate throughput.
- **XXfallback:** Direct XXfallback handshake (2 messages) with pre-generated keys, simulating fallback after a failed IK attempt.

## Transport Throughput

### iOS (Swift / CryptoKit)

| Suite | Encrypt (µs) | Decrypt (µs) | Throughput (MB/s) |
|-------|------------:|------------:|------------------:|
| ChaChaPoly\_SHA256 | 3.4 | 3.6 | 279 |
| ChaChaPoly\_SHA512 | 3.4 | 3.6 | 279 |
| ChaChaPoly\_BLAKE2s | 3.3 | 3.7 | 279 |
| ChaChaPoly\_BLAKE2b | 3.3 | 3.6 | 283 |
| AESGCM\_SHA256 | 2.2 | 2.3 | 429 |
| AESGCM\_SHA512 | 2.2 | 2.4 | 428 |
| AESGCM\_BLAKE2s | 2.2 | 2.4 | 425 |
| AESGCM\_BLAKE2b | 2.2 | 2.4 | 428 |

### Android (Kotlin / JCA on JVM 21)

| Suite | Encrypt (µs) | Decrypt (µs) | Throughput (MB/s) |
|-------|------------:|------------:|------------------:|
| ChaChaPoly\_SHA256 | 2.3 | 2.3 | 211 |
| ChaChaPoly\_SHA512 | 1.7 | 1.7 | 282 |
| ChaChaPoly\_BLAKE2s | 1.2 | 1.3 | 390 |
| ChaChaPoly\_BLAKE2b | 1.3 | 1.3 | 385 |
| AESGCM\_SHA256 | 0.6 | 0.7 | 727 |
| AESGCM\_SHA512 | 0.5 | 0.5 | 1,037 |
| AESGCM\_BLAKE2s | 0.5 | 0.5 | 1,055 |
| AESGCM\_BLAKE2b | 0.5 | 0.5 | 1,056 |

**Key takeaway:** Hash choice does not affect transport speed — after the handshake, only the AEAD cipher is used. AES-GCM is ~1.5× faster than ChaCha20-Poly1305 on iOS (hardware AES-NI) and ~3–5× faster on Android/JVM after Cipher instance caching.

## Handshake Performance (Representative Patterns)

### iOS (Swift / CryptoKit)

Average handshake time in microseconds (µs). All 41 patterns × 8 suites were benchmarked; representative results shown below.

| Suite | N (1) | NN (2) | NK (2) | IK (2) | XX (3) | IKpsk2 (2) |
|-------|------:|-------:|-------:|-------:|-------:|-----------:|
| ChaChaPoly\_SHA256 | 101 | 133 | 190 | 313 | 278 | 349 |
| ChaChaPoly\_SHA512 | 107 | 139 | 197 | 328 | 283 | 374 |
| ChaChaPoly\_BLAKE2s | 511 | 570 | 812 | 1,322 | 1,168 | 1,954 |
| ChaChaPoly\_BLAKE2b | 637 | 706 | 1,007 | 1,637 | 1,382 | 2,428 |
| AESGCM\_SHA256 | 99 | 126 | 186 | 307 | 260 | 337 |
| AESGCM\_SHA512 | 104 | 134 | 197 | 323 | 280 | 365 |
| AESGCM\_BLAKE2s | 502 | 568 | 813 | 1,302 | 1,163 | 1,940 |
| AESGCM\_BLAKE2b | 619 | 697 | 1,000 | 1,634 | 1,377 | 2,413 |

### Android (Kotlin / JCA on JVM 21)

| Suite | N (1) | NN (2) | NK (2) | IK (2) | XX (3) | IKpsk2 (2) |
|-------|------:|-------:|-------:|-------:|-------:|-----------:|
| ChaChaPoly\_SHA256 | 612 | 345 | 495 | 666 | 590 | 655 |
| ChaChaPoly\_SHA512 | 239 | 277 | 412 | 665 | 538 | 668 |
| ChaChaPoly\_BLAKE2s | 232 | 272 | 408 | 665 | 544 | 675 |
| ChaChaPoly\_BLAKE2b | 259 | 269 | 403 | 667 | 516 | 671 |
| AESGCM\_SHA256 | 227 | 276 | 413 | 649 | 539 | 646 |
| AESGCM\_SHA512 | 197 | 260 | 390 | 651 | 522 | 670 |
| AESGCM\_BLAKE2s | 200 | 264 | 399 | 662 | 531 | 662 |
| AESGCM\_BLAKE2b | 199 | 263 | 394 | 660 | 536 | 665 |

**Observations:**
- On iOS, SHA-256 and SHA-512 suites perform nearly identically thanks to CryptoKit hardware acceleration. BLAKE2 suites are 3–4× slower due to the pure-Swift blake-hash implementation.
- On JVM, all hash functions perform similarly because JVM JIT compilation narrows the gap. The one-way `N` pattern shows high variance in early runs due to JIT warmup.
- Handshake time scales with the number of DH operations, not the number of messages. Patterns with more DH tokens (e.g., IK with `es + ss`, KK with `es + ss + se`) are slower than simpler ones (NN with just `ee`).

## XXfallback Handshake

### iOS (Swift / CryptoKit)

| Suite | Avg (µs) | Min (µs) | Max (µs) |
|-------|--------:|---------:|---------:|
| ChaChaPoly\_SHA256 | 234 | 232 | 241 |
| ChaChaPoly\_SHA512 | 256 | 251 | 268 |
| ChaChaPoly\_BLAKE2s | 1,140 | 1,135 | 1,145 |
| ChaChaPoly\_BLAKE2b | 1,471 | 1,464 | 1,482 |
| AESGCM\_SHA256 | 232 | 232 | 236 |
| AESGCM\_SHA512 | 253 | 252 | 259 |
| AESGCM\_BLAKE2s | 1,149 | 1,133 | 1,165 |
| AESGCM\_BLAKE2b | 1,465 | 1,456 | 1,480 |

### Android (Kotlin / JCA on JVM 21)

| Suite | Avg (µs) | Min (µs) | Max (µs) |
|-------|--------:|---------:|---------:|
| ChaChaPoly\_SHA256 | 658 | 647 | 673 |
| ChaChaPoly\_SHA512 | 685 | 656 | 903 |
| ChaChaPoly\_BLAKE2s | 662 | 655 | 680 |
| ChaChaPoly\_BLAKE2b | 663 | 656 | 672 |
| AESGCM\_SHA256 | 650 | 643 | 663 |
| AESGCM\_SHA512 | 659 | 651 | 674 |
| AESGCM\_BLAKE2s | 667 | 655 | 687 |
| AESGCM\_BLAKE2b | 661 | 655 | 671 |

## Running Benchmarks

```bash
# iOS
cd ios && swift test --filter BenchmarkTests

# Android
cd android && ./gradlew test --tests "com.noise.protocol.BenchmarkTests" --info
```

## Test Environment

| | iOS | Android |
|-|-----|---------|
| **Hardware** | Apple M1 | Apple M1 (same machine) |
| **OS** | macOS 14 | JVM (OpenJDK 21.0.10) |
| **Crypto** | CryptoKit (hardware-accelerated) | JCA/JCE (JIT-compiled) |
| **Compiler** | Swift 6.1, Release mode via SPM | Kotlin 2.3.0, JVM target 21 |
| **Iterations** | 5 warmup + 20 measured (handshake), 100 + 1000 (transport) | Same |
