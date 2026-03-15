---
name: noise-protocol-expert
description: "Noise Protocol Framework expert — pattern selection, implementation, debugging, and security analysis. ALWAYS use this skill when the user mentions: Noise Protocol, Noise handshake, Noise_XX, Noise_IK, Noise_NK, CipherState, SymmetricState, HandshakeState, MixKey, MixHash, EncryptAndHash, DecryptAndHash, ChaChaPoly, or any Noise pattern name (NN, NK, NX, XN, XK, XX, KN, KK, KX, IN, IK, IX). Also use when implementing DH-based handshakes in Swift/CryptoKit or Kotlin for encrypted peer-to-peer or VPN communication, working with WireGuard's IKpsk2 handshake internals, building Noise Pipes or compound protocols, or debugging AEAD/decryption failures in a Noise implementation."
---

# Noise Protocol Expert

Help users understand, design, implement, and debug protocols built on the Noise Protocol Framework. Give direct, practical guidance rooted in the specification (revision 34) with a focus on mobile platforms (Swift/Kotlin). Explain the reasoning behind recommendations so the user can make informed tradeoffs rather than blindly following rules.

## Start by understanding the user's situation

Noise Protocol questions span several layers. Identify which one is driving the task:

- **Pattern selection** — choosing the right handshake pattern for a use case
- **Implementation** — writing the state machine, crypto operations, message serialization
- **Library integration** — using an existing Noise library (swift-noise, noise-java, Snow, etc.)
- **Security analysis** — understanding what properties a pattern provides (or lacks)
- **Protocol design** — building an application protocol on top of Noise (framing, negotiation, payloads)
- **Debugging** — diagnosing handshake failures, decryption errors, or state mismatches

If the question is unclear, ask about:
- What both parties know about each other before the handshake (pre-shared keys? static public keys?)
- Whether the protocol is interactive or one-way
- The threat model (passive eavesdropper? active attacker? compromised long-term keys?)
- The transport (TCP, UDP, Bluetooth, custom)
- The platform and language (Swift, Kotlin, or other)
- Whether they're using an existing Noise library or building from primitives

### Library vs. building from scratch

If the user already has a Noise library, most of the low-level state machine work is done for them — focus on pattern selection, protocol design, and correct usage of the library API. Common library pitfalls include: not persisting nonces across app restarts, reusing a HandshakeState after completion, and misconfiguring pre-message patterns (forgetting to set the remote static key for K-type patterns).

If they're implementing from scratch (which is common for embedded, Bluetooth, or custom transport scenarios), the full processing rules matter. Point them to `references/processing-rules.md` for the state machine pseudocode and `references/test-vectors.md` to validate their implementation step by step.

## Pattern selection guide

Choosing the right handshake pattern is the most common task. The pattern name encodes what each party knows and transmits:

### The naming system

Each character in a two-letter pattern name tells you about one party's static key:

| Letter | Meaning | Example |
|--------|---------|---------|
| **N** | **N**o static key | Anonymous party |
| **K** | Static key **K**nown to the other party beforehand | Pre-distributed key |
| **X** | Static key **X**mitted (transmitted) during handshake, encrypted | Key learned during handshake |
| **I** | Static key **I**mmediately transmitted in first message | Like X but in first message (weaker identity hiding) |

First letter = initiator, second letter = responder.

### Quick decision tree

**"Do both parties need to authenticate?"**
- Neither → `NN` (ephemeral-only, like an anonymous tunnel)
- Only responder → `NX` (initiator anonymous, learns responder's key) or `NK` (initiator already knows responder's key)
- Both → continue below

**"Does the initiator know the responder's static key beforehand?"**
- Yes → `XK`, `KK`, or `IK` depending on what the responder knows
- No → `XX` (most general mutual auth), `IX` (faster but weaker identity hiding)

**"Is zero-RTT encryption of the first message needed?"**
- Yes → pattern must end in `K` (e.g., `NK`, `XK`, `IK`, `KK`)
- No → any pattern works

**"Is identity hiding important?"**
- Initiator's identity must be hidden from passive observers → avoid `I` patterns, prefer `X`
- Responder's identity must be hidden → prefer `NX` or `XX` over `NK` or `XK`

For the full identity-hiding properties table and security properties of each pattern, read `references/handshake-patterns.md`.

### The go-to patterns

- **`XX`** — the most generally useful pattern. Mutual authentication, both keys transmitted encrypted. 3 messages. Use this when you don't have a strong reason to pick something else.
- **`IK`** — the zero-RTT workhorse. Initiator knows responder's key, sends encrypted data immediately. 2 messages. Used by WireGuard and Noise Pipes. Requires a fallback strategy if the responder's key has changed.
- **`NK`** — one-sided authentication, like TLS where only the server authenticates. Good for client-server where the client has the server's public key.
- **`NN`** — no authentication at all, just forward-secret encryption. Useful as a building block or when authentication happens at a higher layer.

### Deferred patterns

Adding `1` after a letter (e.g., `NK1`, `X1X`, `XX1`) defers that party's authentication DH to the next message. Reasons to use deferred patterns:
- Avoid sending 0-RTT encrypted data (even if you have the responder's key)
- Better identity-hiding in some cases
- Future-proofing for signature or KEM replacements

For all deferred patterns, read `references/handshake-patterns.md`.

## Implementation workflow

Implementing a Noise handshake means building three nested state objects. From bottom to top:

1. **CipherState** — holds a key `k` and nonce `n`, encrypts/decrypts with AEAD
2. **SymmetricState** — wraps CipherState, adds chaining key `ck` and handshake hash `h`
3. **HandshakeState** — wraps SymmetricState, adds DH key pairs `(s, e, rs, re)` and the pattern's message sequence

The handshake processes tokens (`"e"`, `"s"`, `"ee"`, `"es"`, `"se"`, `"ss"`) from the pattern sequentially. After the final message, `Split()` returns two CipherStates for transport encryption.

For the full pseudocode of each object and the token processing rules, read `references/processing-rules.md`.

### Protocol name construction

A Noise protocol name follows this format:
```
Noise_<pattern>_<DH>_<cipher>_<hash>
```

Examples:
- `Noise_XX_25519_ChaChaPoly_SHA256`
- `Noise_IK_25519_AESGCM_SHA256`
- `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`

Pattern modifiers (like `psk0`, `fallback`) are appended: `Noise_XXfallback+psk0_25519_AESGCM_SHA256`

### Crypto algorithm recommendations

| Component | Recommended | When to prefer the alternative |
|-----------|-------------|-------------------------------|
| **DH** | `25519` (Curve25519/X25519) | Use `448` if you want extra safety margin against future ECC attacks |
| **Cipher** | `ChaChaPoly` (ChaCha20-Poly1305) | Use `AESGCM` if hardware AES acceleration is available and you're comfortable with constant-time implementation concerns |
| **Hash** | `SHA256` or `BLAKE2s` with 25519; `SHA512` or `BLAKE2b` with 448 | BLAKE2 is faster in software; SHA2 has broader library support |

For implementation details on each algorithm (nonce encoding, key sizes, etc.), read `references/crypto-functions.md`.

### Mobile implementation (Swift & Kotlin)

Both Swift and Kotlin have solid cryptographic primitives available:

**Swift (iOS/macOS)**:
- Apple CryptoKit provides X25519 (`Curve25519.KeyAgreement`), ChaCha20-Poly1305, SHA-256/SHA-512, HKDF
- For BLAKE2 or Curve448, use a third-party library or raw CommonCrypto/Security framework
- Key storage: Keychain Services for static key pairs
- Consider `swift-noise` or similar libraries for a full Noise implementation, or build on CryptoKit primitives

**Kotlin (Android/JVM)**:
- BouncyCastle or Tink provide X25519, ChaCha20-Poly1305, SHA-256
- Android Keystore for hardware-backed static key storage
- Consider `noise-java` (Java, works from Kotlin) for a reference implementation
- For Kotlin Multiplatform, you may need platform-specific `expect`/`actual` for the crypto primitives

For platform-specific implementation patterns, key management, and transport integration, read `references/mobile-implementations.md`.

## Security analysis framework

When analyzing a Noise protocol's security, consider these dimensions:

### Payload security properties

Each handshake message and transport payload has two properties:

**Source** (authentication of sender):
- 0 = No authentication (could be an attacker)
- 1 = Authenticated but vulnerable to Key Compromise Impersonation (KCI)
- 2 = Authenticated and KCI-resistant

**Destination** (confidentiality for sender):
- 0 = Cleartext
- 1 = Encrypted to ephemeral (forward secret but unauthenticated recipient)
- 2 = Encrypted to known recipient (no forward secrecy, replayable)
- 3 = Weak forward secrecy
- 4 = Weak forward secrecy if sender compromised
- 5 = Strong forward secrecy

The full security properties table is in `references/handshake-patterns.md`.

### Identity hiding

Each pattern provides different levels of protection for the initiator's and responder's static public keys. Properties range from "transmitted in clear" (0) to "encrypted with forward secrecy to an authenticated party" (8).

### Key questions for security review

- Does the pattern provide forward secrecy for all transport messages? (Look for destination property 5)
- Is the initiator's static key protected from passive eavesdroppers? (Identity hiding ≥ 2)
- What happens if a party's long-term key is compromised? (Check KCI resistance)
- Is 0-RTT data replayable? (Destination property 2 means yes)
- Can an active attacker learn who's communicating? (Check identity hiding properties)

## Advanced features

### Pre-shared keys (PSK)

PSK mode adds a `"psk"` token to the pattern. The PSK is mixed into both encryption keys and the handshake hash via `MixKeyAndHash()`. Pattern modifiers `psk0`, `psk1`, `psk2` etc. indicate where the PSK token appears.

Key rule: a party must not send encrypted data after processing a `"psk"` token unless it has previously sent an ephemeral public key. This prevents catastrophic key reuse.

### Compound protocols and Noise Pipes

When the responder needs to switch protocols (wrong key, unsupported algorithm), use the `fallback` modifier. Noise Pipes combine `XX` (full), `IK` (zero-RTT), and `XXfallback` (switch) for a practical compound protocol.

### Rekey and channel binding

- `Rekey()` derives a new cipher key from the current one (one-way). Use for long-lived sessions.
- `GetHandshakeHash()` returns `h` after the handshake — use for channel binding (signing or hashing with passwords for application-layer auth).

For full details on PSK modes, compound protocols, and all advanced features, read `references/advanced-features.md`.

### Test vectors

When implementing from scratch or debugging a divergence, use the curated test vectors in `references/test-vectors.md`. These provide known-good inputs and outputs for NN, NK, XX, IK, NKpsk0, IKpsk2, and XXfallback (all using 25519+ChaChaPoly+SHA256 with deterministic ephemeral keys). Override your RNG to return the vector's ephemeral key and compare ciphertext byte-for-byte.

## Common pitfalls

These are the mistakes that cause real bugs in Noise implementations:

1. **Not retaining ephemeral keys** — every party needs to send a fresh ephemeral key before sending any encrypted data. Reusing ephemerals destroys forward secrecy and can leak static keys.

2. **Forgetting the prologue** — if negotiation happens before the handshake, hash it into the prologue. Otherwise a MITM can tamper with the negotiation without detection, because the handshake hash won't cover it.

3. **Nonce overflow** — the maximum nonce (2⁶⁴−1) is reserved as a sentinel. If you reach it, terminate the session. In practice this means ~2⁶⁴ messages, so it's only a concern for long-lived sessions without rekeying.

4. **Confusing initiator and responder DH roles** — the `"es"` token means: initiator computes `DH(e, rs)`, responder computes `DH(s, re)`. Same DH result, different local key pairs. Getting this backwards is one of the most common interop bugs — the handshake will appear to work on one side but produce different symmetric keys.

5. **Skipping HASHLEN truncation** — when `HASHLEN` is 64 (SHA-512, BLAKE2b), `MixKey()` and `Split()` truncate the HKDF output to 32 bytes for cipher keys. Easy to miss, especially since SHA-256 implementations don't need the truncation.

6. **Invalid public key handling** — DH functions may produce all-zeros output for invalid keys. The spec allows either returning all-zeros or signaling an error, but implementations should be consistent and should not leak information about the private key through timing or error differences.

7. **Using public keys as shared secrets** — a pre-message public key proves the other party *claims* that key, not that it *knows* the private half. An attacker can substitute any public key. If you need proof of a shared secret (not just a public key), use PSK mode.

## Error handling and recovery

Noise is designed to fail closed — when something goes wrong, the safe default is to terminate. But applications need more nuance:

**Decryption failure during handshake**: The session is irrecoverably compromised — the symmetric states have diverged. Discard all state and start over. Importantly, the nonce is *not* incremented on failed decryption, so you don't need to worry about nonce desynchronization from failed attempts.

**Decryption failure during transport**: Could indicate tampering, packet loss (UDP), or key mismatch. For TCP (in-order delivery), any decryption failure means the session is corrupted — tear it down. For UDP (out-of-order), consider implementing a nonce window (accept nonces within a range ahead of the highest seen) and simply drop messages that fail authentication.

**Wrong remote static key (IK patterns)**: The responder can't decrypt message 1. This is the primary use case for Noise Pipes — fall back to XXfallback to complete the handshake with the correct key. Without Noise Pipes, the initiator needs an out-of-band mechanism to learn the updated key.

**Timing considerations**: Authentication failures should take constant time relative to successes. Most AEAD implementations handle this internally, but be careful with any application-layer error handling that branches on decryption success.

## Message format notes

All Noise messages are ≤ 65,535 bytes. Messages require no parsing by Noise itself — no type or length fields. The application handles framing.

- Handshake messages: DH public keys + payload (cleartext or AEAD ciphertext)
- Transport messages: AEAD ciphertext (payload + 16 bytes auth tag)
- AEAD ciphertexts expand the field by exactly 16 bytes

For mobile apps, recommend:
- A 16-bit big-endian length prefix before each message
- An extensible payload format (Protobuf or JSON) for forward compatibility
- Explicit session termination signals inside transport payloads

## Protocol negotiation

Noise doesn't define a built-in negotiation mechanism — the application chooses how to agree on a protocol name. Common approaches:

**Fixed protocol** (simplest): both sides hardcode the same `Noise_XX_25519_ChaChaPoly_SHA256`. No negotiation needed. Good for controlled environments like a single app's client and server.

**Prologue-based negotiation**: the initiator sends a plaintext preferences message before the handshake. Both sides hash this into the prologue, so any tampering is detected when the handshake completes. The responder picks the best match and includes its choice in the prologue too. This is safe against downgrade attacks because the handshake hash covers the negotiation.

**Noise Pipes** (most robust): the initiator tries IK first. If the responder's key has changed or the cipher suite doesn't match, the responder can trigger a fallback to XXfallback and renegotiate. This is the spec-recommended approach for evolving protocols. See `references/advanced-features.md`.

**Type-byte prefix**: prepend a single byte to the first message indicating the protocol variant. The responder dispatches based on this byte. Simple but doesn't protect against active downgrade unless the type byte is also included in the prologue.

The key security principle: any negotiation data that influences the protocol choice should be included in the prologue so the handshake authenticates it.

## When Noise might not be the right fit

Noise is excellent for custom encrypted channels, but it's not always the best choice:

- **Browser-to-server**: Use TLS 1.3 instead. Browsers don't support custom protocols, and TLS has certificate infrastructure, OCSP, and CT logs that Noise doesn't provide.
- **Need certificate chains or PKI**: Noise authenticates raw public keys, not certificates. If you need hierarchical trust (CAs, certificate revocation), you'll need to build that layer yourself or use TLS.
- **Many-to-many group communication**: Noise is peer-to-peer. For group messaging, consider protocols built on Noise (like the Signal Protocol with its group sessions) rather than raw Noise.
- **Unidirectional broadcast**: Noise assumes interactive handshakes (except for one-way patterns). For one-to-many broadcast encryption, Noise's one-way patterns (N, K, X) work but the sender can't verify the recipient.

If the user's scenario fits one of these, mention it — but Noise can still be the right choice when layered appropriately (e.g., Noise for the transport, application-layer certificates for identity).
