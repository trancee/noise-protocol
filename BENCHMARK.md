# Benchmark Results

Performance benchmarks for all 8 cipher suites across all handshake patterns and transport operations. Results collected on Apple M1 (macOS 14, ARM64) — iOS benchmarks use CryptoKit (Swift), Android benchmarks use JCA/JCE (Kotlin/JVM 21).

> **Note:** These are micro-benchmarks on development hardware. Real-world performance varies by device, OS version, and system load. BLAKE2 suites use a pure-Swift/pure-Kotlin implementation ([blake-hash](https://github.com/trancee/blake-hash)) and are significantly slower than SHA-based suites which use hardware-accelerated platform APIs.

## Quick Summary

| Metric | ChaChaPoly + SHA-256 | AES-GCM + SHA-256 |
|--------|---------------------|--------------------|
| NN handshake (2 msgs) | ~130 µs (iOS) / ~370 µs (JVM) | ~125 µs (iOS) / ~360 µs (JVM) |
| XX handshake (3 msgs) | ~270 µs (iOS) / ~590 µs (JVM) | ~260 µs (iOS) / ~570 µs (JVM) |
| IK handshake (2 msgs) | ~320 µs (iOS) / ~690 µs (JVM) | ~310 µs (iOS) / ~670 µs (JVM) |
| Transport encrypt 1 KB | 3.3 µs (iOS) / 2.4 µs (JVM) | 2.2 µs (iOS) / 0.7 µs (JVM) |
| Transport throughput | ~280 MB/s (iOS) / ~205 MB/s (JVM) | ~430 MB/s (iOS) / ~716 MB/s (JVM) |

## Performance Optimizations

The codebase was profiled and optimized across both platforms. Key changes and their impact:

### Optimizations Applied

| Optimization | Platform | Impact |
|---|---|---|
| **Cache DH public key** — stored computed public key instead of recalculating on every access | Both | Handshake: 20–30% faster (iOS), ~2% faster (Android) |
| **HKDF counter constants** — pre-allocated `[0x01]`, `[0x02]`, `[0x03]` as static constants | Both | Eliminates per-call allocations in every MixKey/Split |
| **BLAKE2 HMAC loop optimization** — replaced `map` closure with explicit for-loop for ipad/opad XOR | Both | Reduces closure overhead in BLAKE2 suites |
| **Pre-sized handshake buffer** — `Data(capacity: 256)` (iOS), `ByteArrayOutputStream(256)` (Android) | Both | Eliminates buffer regrowth during writeMessage |
| **ThreadLocal Cipher caching** — reuse JCA `Cipher` instances via `ThreadLocal` | Android | Transport: **2× faster** for AES-GCM |
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
| ChaChaPoly\_SHA256 | 197 | 205 | +4% |
| ChaChaPoly\_BLAKE2s | 326 | 400 | **+23%** |
| ChaChaPoly\_BLAKE2b | 322 | 399 | **+24%** |
| AESGCM\_SHA256 | 348 | 716 | **+106%** |
| AESGCM\_SHA512 | 365 | 1,061 | **+191%** |
| AESGCM\_BLAKE2s | 377 | 1,061 | **+182%** |
| AESGCM\_BLAKE2b | 381 | 1,089 | **+186%** |

> The AES-GCM gains come from `ThreadLocal<Cipher>` caching, avoiding `Cipher.getInstance()` lookups on every encrypt/decrypt. ChaCha20-Poly1305 also benefits, but less dramatically because JCA's ChaCha20 provider has a key+nonce reuse check that requires occasional fallback to a fresh instance.

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
| ChaChaPoly\_SHA256 | 2.4 | 2.4 | 205 |
| ChaChaPoly\_SHA512 | 1.6 | 2.6 | 234 |
| ChaChaPoly\_BLAKE2s | 1.2 | 1.2 | 400 |
| ChaChaPoly\_BLAKE2b | 1.2 | 1.2 | 399 |
| AESGCM\_SHA256 | 0.7 | 0.6 | 716 |
| AESGCM\_SHA512 | 0.5 | 0.5 | 1,061 |
| AESGCM\_BLAKE2s | 0.5 | 0.5 | 1,061 |
| AESGCM\_BLAKE2b | 0.5 | 0.4 | 1,089 |

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
| ChaChaPoly\_SHA256 | 745 | 366 | 524 | 690 | 588 | 679 |
| ChaChaPoly\_SHA512 | 274 | 287 | 424 | 699 | 557 | 692 |
| ChaChaPoly\_BLAKE2s | 251 | 275 | 407 | 667 | 548 | 682 |
| ChaChaPoly\_BLAKE2b | 255 | 268 | 403 | 661 | 540 | 669 |
| AESGCM\_SHA256 | 227 | 270 | 395 | 668 | 527 | 674 |
| AESGCM\_SHA512 | 210 | 260 | 389 | 660 | 519 | 668 |
| AESGCM\_BLAKE2s | 205 | 269 | 401 | 661 | 537 | 678 |
| AESGCM\_BLAKE2b | 202 | 261 | 393 | 662 | 528 | 670 |

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
| ChaChaPoly\_SHA256 | 673 | 646 | 718 |
| ChaChaPoly\_SHA512 | 697 | 669 | 969 |
| ChaChaPoly\_BLAKE2s | 675 | 666 | 699 |
| ChaChaPoly\_BLAKE2b | 677 | 668 | 701 |
| AESGCM\_SHA256 | 676 | 660 | 738 |
| AESGCM\_SHA512 | 669 | 650 | 782 |
| AESGCM\_BLAKE2s | 672 | 664 | 685 |
| AESGCM\_BLAKE2b | 681 | 668 | 712 |

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
| **Compiler** | Swift 6.0, Release mode via SPM | Kotlin 2.3.0, JVM target 21 |
| **Iterations** | 5 warmup + 20 measured (handshake), 100 + 1000 (transport) | Same |
