# Benchmark Results

Performance benchmarks for all 8 cipher suites across all handshake patterns and transport operations. Results collected on Apple M1 (macOS 14, ARM64) — iOS benchmarks use CryptoKit (Swift), Android benchmarks use JCA/JCE (Kotlin/JVM 21).

> **Note:** These are micro-benchmarks on development hardware. Real-world performance varies by device, OS version, and system load. BLAKE2 suites use a pure-Swift/pure-Kotlin implementation ([blake-hash](https://github.com/trancee/blake-hash)) and are significantly slower than SHA-based suites which use hardware-accelerated platform APIs.

## Quick Summary

| Metric | ChaChaPoly + SHA-256 | AES-GCM + SHA-256 |
|--------|---------------------|--------------------|
| NN handshake (2 msgs) | ~180 µs (iOS) / ~400 µs (JVM) | ~170 µs (iOS) / ~370 µs (JVM) |
| XX handshake (3 msgs) | ~365 µs (iOS) / ~640 µs (JVM) | ~350 µs (iOS) / ~610 µs (JVM) |
| IK handshake (2 msgs) | ~400 µs (iOS) / ~710 µs (JVM) | ~385 µs (iOS) / ~680 µs (JVM) |
| Transport encrypt 1 KB | 3.3 µs (iOS) / 2.4 µs (JVM) | 2.2 µs (iOS) / 1.4 µs (JVM) |
| Transport throughput | ~280 MB/s (iOS) / ~200 MB/s (JVM) | ~425 MB/s (iOS) / ~340 MB/s (JVM) |

## Methodology

- **Handshake:** Full initiator↔responder handshake with key generation outside the timed section. 5 warmup iterations + 20 measured iterations. Reports average, min, and max.
- **Transport:** After completing an NN handshake, encrypt and decrypt a 1 KB payload. 100 warmup + 1000 measured iterations. Reports per-operation time and aggregate throughput.
- **XXfallback:** Direct XXfallback handshake (2 messages) with pre-generated keys, simulating fallback after a failed IK attempt.

## Transport Throughput

### iOS (Swift / CryptoKit)

| Suite | Encrypt (µs) | Decrypt (µs) | Throughput (MB/s) |
|-------|------------:|------------:|------------------:|
| ChaChaPoly\_SHA256 | 3.3 | 3.6 | 282 |
| ChaChaPoly\_SHA512 | 3.3 | 3.6 | 285 |
| ChaChaPoly\_BLAKE2s | 3.2 | 3.6 | 285 |
| ChaChaPoly\_BLAKE2b | 3.2 | 3.6 | 286 |
| AESGCM\_SHA256 | 2.2 | 2.4 | 425 |
| AESGCM\_SHA512 | 2.2 | 2.4 | 430 |
| AESGCM\_BLAKE2s | 2.2 | 2.4 | 428 |
| AESGCM\_BLAKE2b | 2.2 | 2.4 | 428 |

### Android (Kotlin / JCA on JVM 21)

| Suite | Encrypt (µs) | Decrypt (µs) | Throughput (MB/s) |
|-------|------------:|------------:|------------------:|
| ChaChaPoly\_SHA256 | 2.4 | 2.4 | 200 |
| ChaChaPoly\_SHA512 | 1.5 | 1.5 | 318 |
| ChaChaPoly\_BLAKE2s | 1.5 | 1.5 | 326 |
| ChaChaPoly\_BLAKE2b | 1.5 | 1.5 | 324 |
| AESGCM\_SHA256 | 1.4 | 1.4 | 343 |
| AESGCM\_SHA512 | 1.3 | 1.3 | 376 |
| AESGCM\_BLAKE2s | 1.3 | 1.3 | 379 |
| AESGCM\_BLAKE2b | 1.3 | 1.3 | 375 |

**Key takeaway:** Hash choice does not affect transport speed — after the handshake, only the AEAD cipher is used. AES-GCM is ~1.5× faster than ChaCha20-Poly1305 for transport on both platforms, thanks to hardware AES-NI/ARMv8 acceleration.

## Handshake Performance (Representative Patterns)

### iOS (Swift / CryptoKit)

Average handshake time in microseconds (µs). All 41 patterns × 8 suites were benchmarked; representative results shown below.

| Suite | N (1) | NN (2) | NK (2) | IK (2) | XX (3) | IKpsk2 (2) |
|-------|------:|-------:|-------:|-------:|-------:|-----------:|
| ChaChaPoly\_SHA256 | 129 | 178 | 247 | 399 | 364 | 483 |
| ChaChaPoly\_SHA512 | 134 | 185 | 250 | 409 | 376 | 514 |
| ChaChaPoly\_BLAKE2s | 516 | 601 | 857 | 1403 | 1240 | 2106 |
| ChaChaPoly\_BLAKE2b | 641 | 731 | 1050 | 1706 | 1452 | 2583 |
| AESGCM\_SHA256 | 185 | 170 | 239 | 385 | 353 | 485 |
| AESGCM\_SHA512 | 130 | 180 | 246 | 399 | 365 | 485 |
| AESGCM\_BLAKE2s | 515 | 597 | 857 | 1386 | 1232 | 2068 |
| AESGCM\_BLAKE2b | 635 | 730 | 1042 | 1681 | 1432 | 2551 |

### Android (Kotlin / JCA on JVM 21)

| Suite | N (1) | NN (2) | NK (2) | IK (2) | XX (3) | IKpsk2 (2) |
|-------|------:|-------:|-------:|-------:|-------:|-----------:|
| ChaChaPoly\_SHA256 | 801 | 403 | 568 | 715 | 643 | 698 |
| ChaChaPoly\_SHA512 | 305 | 295 | 434 | 714 | 562 | 696 |
| ChaChaPoly\_BLAKE2s | 259 | 281 | 417 | 673 | 554 | 687 |
| ChaChaPoly\_BLAKE2b | 278 | 265 | 403 | 671 | 543 | 679 |
| AESGCM\_SHA256 | 227 | 274 | 399 | 670 | 530 | 675 |
| AESGCM\_SHA512 | 208 | 267 | 394 | 671 | 533 | 676 |
| AESGCM\_BLAKE2s | 208 | 273 | 400 | 668 | 542 | 682 |
| AESGCM\_BLAKE2b | 202 | 271 | 401 | 674 | 541 | 679 |

**Observations:**
- On iOS, SHA-256 and SHA-512 suites perform nearly identically thanks to CryptoKit hardware acceleration. BLAKE2 suites are 3–4× slower due to the pure-Swift blake-hash implementation.
- On JVM, all hash functions perform similarly because JVM JIT compilation narrows the gap. The one-way `N` pattern shows high variance in early runs due to JIT warmup.
- Handshake time scales with the number of DH operations, not the number of messages. Patterns with more DH tokens (e.g., IK with `es + ss`, KK with `es + ss + se`) are slower than simpler ones (NN with just `ee`).

## XXfallback Handshake

### iOS (Swift / CryptoKit)

| Suite | Avg (µs) | Min (µs) | Max (µs) |
|-------|--------:|---------:|---------:|
| ChaChaPoly\_SHA256 | 308 | 306 | 315 |
| ChaChaPoly\_SHA512 | 327 | 321 | 357 |
| ChaChaPoly\_BLAKE2s | 1131 | 1125 | 1141 |
| ChaChaPoly\_BLAKE2b | 1353 | 1346 | 1361 |
| AESGCM\_SHA256 | 308 | 306 | 314 |
| AESGCM\_SHA512 | 325 | 321 | 337 |
| AESGCM\_BLAKE2s | 1136 | 1127 | 1162 |
| AESGCM\_BLAKE2b | 1351 | 1338 | 1391 |

### Android (Kotlin / JCA on JVM 21)

| Suite | Avg (µs) | Min (µs) | Max (µs) |
|-------|--------:|---------:|---------:|
| ChaChaPoly\_SHA256 | 669 | 655 | 698 |
| ChaChaPoly\_SHA512 | 686 | 669 | 771 |
| ChaChaPoly\_BLAKE2s | 679 | 659 | 727 |
| ChaChaPoly\_BLAKE2b | 680 | 673 | 708 |
| AESGCM\_SHA256 | 676 | 655 | 717 |
| AESGCM\_SHA512 | 677 | 670 | 692 |
| AESGCM\_BLAKE2s | 675 | 666 | 690 |
| AESGCM\_BLAKE2b | 676 | 664 | 687 |

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
