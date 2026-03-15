# Processing Rules Reference

## Table of Contents
1. [CipherState](#cipherstate)
2. [SymmetricState](#symmetricstate)
3. [HandshakeState](#handshakestate)
4. [Token processing summary](#token-processing-summary)
5. [Transport phase](#transport-phase)

---

## CipherState

The lowest-level object. Holds an encryption key and nonce.

### Variables
- **`k`**: 32-byte cipher key (may be `empty`, meaning not yet initialized)
- **`n`**: 8-byte (64-bit) unsigned integer nonce

### Functions

**`InitializeKey(key)`**
Sets `k = key`, `n = 0`.

**`HasKey()`**
Returns true if `k` is non-empty.

**`SetNonce(nonce)`**
Sets `n = nonce`. Used for out-of-order transport messages.

**`EncryptWithAd(ad, plaintext)`**
If `k` is non-empty: returns `ENCRYPT(k, n++, ad, plaintext)`.
Otherwise: returns `plaintext`.

**`DecryptWithAd(ad, ciphertext)`**
If `k` is non-empty: returns `DECRYPT(k, n++, ad, ciphertext)`.
Otherwise: returns `ciphertext`.
On authentication failure: `n` is NOT incremented, error is signaled.

**`Rekey()`**
Sets `k = REKEY(k)`.

### Nonce rules
- `n++` means "use current value, then increment"
- Maximum `n` value (2⁶⁴−1) is reserved
- If incrementing `n` would reach 2⁶⁴−1, signal an error (no more encrypt/decrypt allowed)
- Nonce wrap-around must never happen

---

## SymmetricState

Wraps a CipherState and adds the chaining key and handshake hash.

### Variables
- **`ck`**: Chaining key, `HASHLEN` bytes
- **`h`**: Handshake hash, `HASHLEN` bytes

### Functions

**`InitializeSymmetric(protocol_name)`**
Takes the protocol name byte sequence.
- If `protocol_name` ≤ `HASHLEN` bytes: set `h = protocol_name` padded with zeros to `HASHLEN`
- Otherwise: set `h = HASH(protocol_name)`
- Set `ck = h`
- Call `InitializeKey(empty)`

**`MixKey(input_key_material)`**
- `ck, temp_k = HKDF(ck, input_key_material, 2)`
- If `HASHLEN` is 64: truncate `temp_k` to 32 bytes
- Call `InitializeKey(temp_k)`

**`MixHash(data)`**
- `h = HASH(h || data)`

**`MixKeyAndHash(input_key_material)`**
Used for PSK mode.
- `ck, temp_h, temp_k = HKDF(ck, input_key_material, 3)`
- Call `MixHash(temp_h)`
- If `HASHLEN` is 64: truncate `temp_k` to 32 bytes
- Call `InitializeKey(temp_k)`

**`GetHandshakeHash()`**
Returns `h`. Only call after `Split()`. Used for channel binding.

**`EncryptAndHash(plaintext)`**
- `ciphertext = EncryptWithAd(h, plaintext)`
- Call `MixHash(ciphertext)`
- Return `ciphertext`

Note: if `k` is empty, ciphertext equals plaintext (no encryption).

**`DecryptAndHash(ciphertext)`**
- `plaintext = DecryptWithAd(h, ciphertext)`
- Call `MixHash(ciphertext)`
- Return `plaintext`

Note: if `k` is empty, plaintext equals ciphertext. Important: `MixHash` is called with the *ciphertext*, not the plaintext.

**`Split()`**
Returns two CipherState objects for transport.
- `temp_k1, temp_k2 = HKDF(ck, zerolen, 2)` (zerolen = zero-length byte sequence)
- If `HASHLEN` is 64: truncate both to 32 bytes
- Create `c1`, `c2` CipherStates
- `c1.InitializeKey(temp_k1)`, `c2.InitializeKey(temp_k2)`
- Return `(c1, c2)`

`c1` encrypts initiator→responder messages, `c2` encrypts responder→initiator messages.

---

## HandshakeState

The top-level object. Wraps SymmetricState and manages DH key pairs and the pattern.

### Variables
- **`s`**: Local static key pair (may be empty)
- **`e`**: Local ephemeral key pair (may be empty)
- **`rs`**: Remote static public key (may be empty)
- **`re`**: Remote ephemeral public key (may be empty)
- **`initiator`**: Boolean — true for initiator, false for responder
- **`message_patterns`**: Remaining sequence of message patterns from the handshake pattern

### Initialize

**`Initialize(handshake_pattern, initiator, prologue, s, e, rs, re)`**

1. Derive `protocol_name` from the handshake pattern and crypto function names (see Protocol Names)
2. Call `InitializeSymmetric(protocol_name)`
3. Call `MixHash(prologue)`
4. Set `initiator`, `s`, `e`, `rs`, `re` from arguments
5. Call `MixHash()` for each public key listed in pre-messages:
   - Initiator's pre-message keys first (if both parties have pre-messages)
   - Multiple keys in listed order
6. Set `message_patterns` from the handshake pattern

### WriteMessage

**`WriteMessage(payload, message_buffer)`**

Fetch and delete the next message pattern. Process each token:

- **`"e"`**: Set `e = GENERATE_KEYPAIR()`. Append `e.public_key` to buffer. Call `MixHash(e.public_key)`.
- **`"s"`**: Append `EncryptAndHash(s.public_key)` to buffer.
- **`"ee"`**: Call `MixKey(DH(e, re))`.
- **`"es"`**: Initiator calls `MixKey(DH(e, rs))`. Responder calls `MixKey(DH(s, re))`.
- **`"se"`**: Initiator calls `MixKey(DH(s, re))`. Responder calls `MixKey(DH(e, rs))`.
- **`"ss"`**: Call `MixKey(DH(s, rs))`.

After all tokens: append `EncryptAndHash(payload)` to buffer.

If no more message patterns remain: return `Split()` (two CipherStates).

### ReadMessage

**`ReadMessage(message, payload_buffer)`**

Fetch and delete the next message pattern. Process each token:

- **`"e"`**: Set `re` = next `DHLEN` bytes from message. Call `MixHash(re.public_key)`.
- **`"s"`**: If `HasKey()`: set `temp` = next `DHLEN + 16` bytes. Else: `temp` = next `DHLEN` bytes. Set `rs = DecryptAndHash(temp)`.
- **`"ee"`**: Call `MixKey(DH(e, re))`.
- **`"es"`**: Initiator calls `MixKey(DH(e, rs))`. Responder calls `MixKey(DH(s, re))`.
- **`"se"`**: Initiator calls `MixKey(DH(s, re))`. Responder calls `MixKey(DH(e, rs))`.
- **`"ss"`**: Call `MixKey(DH(s, rs))`.

After all tokens: call `DecryptAndHash()` on remaining bytes, store in payload_buffer.

If no more message patterns remain: return `Split()` (two CipherStates).

---

## Token processing summary

Quick reference for the DH operations in each token:

| Token | Initiator performs | Responder performs |
|-------|-------------------|-------------------|
| `"ee"` | `DH(e, re)` | `DH(e, re)` |
| `"es"` | `DH(e, rs)` | `DH(s, re)` |
| `"se"` | `DH(s, re)` | `DH(e, rs)` |
| `"ss"` | `DH(s, rs)` | `DH(s, rs)` |

Both parties always compute the same DH shared secret — they just use different private/public key inputs to get there (because what's "local" and "remote" is swapped).

The first letter of the token name refers to the *initiator's* key type, the second to the *responder's*. So `"es"` = initiator's ephemeral × responder's static.

---

## Transport phase

After the final handshake message:
- `Split()` returns `(c1, c2)`
- `c1` is used by the initiator to encrypt, and by the responder to decrypt
- `c2` is used by the responder to encrypt, and by the initiator to decrypt
- Transport messages are encrypted/decrypted with `EncryptWithAd`/`DecryptWithAd` using zero-length associated data
- The HandshakeState and SymmetricState can be deleted (except `h` if needed for channel binding)
- If nonce is exhausted (reaching 2⁶⁴−1): delete the CipherState and terminate the session

### Error recovery

**Decryption failure behavior**: When `DecryptWithAd` fails, the nonce `n` is NOT incremented — the CipherState remains in the same state as before the attempt. This is important because it means:

- **TCP (ordered delivery)**: A decryption failure means the stream is corrupted. The sender's nonce has advanced (it encrypted successfully), but the receiver's hasn't. The states are now permanently out of sync. Terminate the session and re-handshake.

- **UDP (out-of-order delivery)**: Decryption failure could mean reordering, packet loss, or tampering. Since the nonce isn't incremented on failure, you can safely try another nonce or discard the message without corrupting state. Use a nonce window to accept messages within a range.

**Handshake failure**: If any handshake message fails to decrypt, the entire handshake is invalid. Both sides should discard all handshake state (keys, symmetric state, everything) and start fresh. Do not attempt to "resume" a failed handshake — the symmetric states have diverged and cannot be reconciled.

**Application guidance**:
- Never reveal *why* decryption failed (timing or error message). Just signal "failure."
- For long-lived sessions, implement rekeying (see advanced-features.md) rather than relying on a single key pair for millions of messages.
- Consider periodic re-handshakes for sessions lasting hours or days — this provides fresh forward secrecy.
