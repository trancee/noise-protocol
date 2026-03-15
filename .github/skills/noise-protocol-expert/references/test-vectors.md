# Noise Protocol Test Vectors

Reference test vectors for validating Noise Protocol implementations. These vectors use deterministic ephemeral keys so you can check your intermediate and final states against known-good values.

Read this file when the user is implementing Noise from scratch, debugging a handshake that produces wrong ciphertext, or wants to validate their implementation against test vectors.

## Table of Contents

- [How to Use Test Vectors](#how-to-use-test-vectors)
- [Vector Format](#vector-format)
- [Shared Key Material](#shared-key-material)
- [NN Vector](#nn---noise_nn_25519_chachapoly_sha256)
- [NK Vector](#nk---noise_nk_25519_chachapoly_sha256)
- [XX Vector](#xx---noise_xx_25519_chachapoly_sha256)
- [IK Vector](#ik---noise_ik_25519_chachapoly_sha256)
- [NKpsk0 Vector](#nkpsk0---noise_nkpsk0_25519_chachapoly_sha256)
- [IKpsk2 (WireGuard-style) Vector](#ikpsk2---noise_ikpsk2_25519_chachapoly_sha256)
- [XXfallback (Noise Pipes) Vector](#xxfallback---noise_xxfallback_25519_chachapoly_sha256)
- [Full Vector Sources](#full-vector-sources)

## How to Use Test Vectors

1. **Override your random number generator** to return the deterministic ephemeral keys from the vector instead of random bytes
2. **Set the prologue** to the hex-decoded prologue value
3. **Set static/remote-static keys** as specified (some patterns don't use all keys)
4. **Process each message** in order, alternating initiator→responder starting with the initiator
5. **Compare ciphertext** output byte-for-byte against the vector's ciphertext
6. **Compare handshake_hash** after the handshake completes (both sides should match)

Messages beyond the handshake length are transport messages. For a 2-message pattern like NN, messages[0] and messages[1] are handshake messages, and messages[2..5] are transport messages.

### Debugging tips

- If message 1 ciphertext matches but message 2 diverges → check the DH computation for asymmetric tokens (es, se)
- If all handshake messages match but transport diverges → check that Split() correctly derives the two CipherState objects
- If the very first bytes are wrong → check that you're using the ephemeral key from the vector, not a random one
- Compare `h` and `ck` after each token on both sides to isolate where state diverges

## Vector Format

All values are hex-encoded. The format follows the [Noise test vector wiki](https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors).

```
{
  "protocol_name": "Noise_XX_25519_ChaChaPoly_SHA256",
  "init_prologue": "hex",       // Initiator's prologue
  "init_static": "hex",         // Initiator's static private key (if pattern uses s)
  "init_ephemeral": "hex",      // Initiator's ephemeral private key (deterministic for testing)
  "init_remote_static": "hex",  // Initiator's pre-known responder static PUBLIC key (K patterns)
  "init_psks": ["hex", ...],    // PSKs for initiator (if psk pattern)
  "resp_prologue": "hex",       // Responder's prologue
  "resp_static": "hex",         // Responder's static private key (if pattern uses s)
  "resp_ephemeral": "hex",      // Responder's ephemeral private key (deterministic for testing)
  "resp_remote_static": "hex",  // Responder's pre-known initiator static PUBLIC key (K patterns)
  "resp_psks": ["hex", ...],    // PSKs for responder (if psk pattern)
  "handshake_hash": "hex",      // Expected h value after handshake completes (both sides)
  "messages": [
    {"payload": "hex", "ciphertext": "hex"},  // Message 1: initiator → responder
    {"payload": "hex", "ciphertext": "hex"},  // Message 2: responder → initiator
    ...                                        // Alternates, handshake then transport
  ]
}
```

Key points:
- `init_static` and `resp_static` are **private** keys (32 bytes for X25519)
- `init_remote_static` is a **public** key (the public half of `resp_static`)
- Ciphertext includes the ephemeral public key, encrypted static key, encrypted payload, and AEAD tags
- Messages alternate: odd indices are initiator→responder, even are responder→initiator

## Shared Key Material

All vectors below use X25519 + ChaChaPoly + SHA256. The same key material is reused across patterns:

| Key | Hex (private) |
|-----|---------------|
| Initiator ephemeral | `893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a` |
| Responder ephemeral | `bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b` |
| Initiator static | `e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1` |
| Responder static | `4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893` |
| Responder static **public** | `31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62` |
| Initiator static **public** | `(derive from init_static with X25519 basepoint)` |
| Prologue | `4a6f686e2047616c74` ("John Galt") |
| PSK (where used) | `54686973206973206d7920417573747269616e20706572737065637469766521` ("This is my Austrian perspective!") |

The first ephemeral public key bytes are always `ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944` (initiator) and `95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843` (responder).

## NN — Noise_NN_25519_ChaChaPoly_SHA256

Pattern: `-> e` / `<- e, ee`
No static keys. Simplest handshake — useful as a baseline test.

```
handshake_hash: 9223fec1b892ec9d0dc2fb3bbeb261f170d1ea679f9c44ccf34aa131b4f5d97e

Message 1 (-> e):
  payload:    4c756477696720766f6e204d69736573
  ciphertext: ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944
              4c756477696720766f6e204d69736573

Message 2 (<- e, ee):
  payload:    4d757272617920526f746862617264
  ciphertext: 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843
              a0ff96bdf86b579ef7dbf94e812a7470b903c20a85a87e3a1fe863264ae547

Transport 1 (initiator → responder):
  payload:    462e20412e20486179656b
  ciphertext: eb1a3e3d80c1792b1bb9cb0e1382f8d8322bfb1ca7c4c8517bb686

Transport 2 (responder → initiator):
  payload:    4361726c204d656e676572
  ciphertext: c781b198d2a974eb1da2c7d518c000cf6396de87ca540963c03713
```

Note: Message 1 payload is sent in the clear (no shared secret yet). The ciphertext is just `e.public || payload`. After `ee` in message 2, the payload is encrypted.

## NK — Noise_NK_25519_ChaChaPoly_SHA256

Pattern: `<- s` / `-> e, es` / `<- e, ee`
Initiator knows responder's static key. 0-RTT capable.

```
handshake_hash: 2efa38a9c7c93ac98f3a097af25c2f58b9e7673787717bc27e98827118c2c1a5

Message 1 (-> e, es):
  payload:    4c756477696720766f6e204d69736573
  ciphertext: ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944
              8134d00711fdb390a0d178fa008f6d47d2891e5ea18ae136c3b4c23ac384efb0

Message 2 (<- e, ee):
  payload:    4d757272617920526f746862617264
  ciphertext: 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843
              8ea16e3701bc0d77744f117bee22451c9afa7f4cdbbcff00c04a8ee0913c88

Transport 1 (initiator → responder):
  payload:    462e20412e20486179656b
  ciphertext: a62de29ce27cb80245d440d986ed816c156e9d757d7008df2198b0

Transport 2 (responder → initiator):
  payload:    4361726c204d656e676572
  ciphertext: 174a35f11c689f4530d7208618e0564ae12f2f50ba8eb4df5382ff
```

Note: Message 1 payload IS encrypted (via `es` DH) — compare with NN where it was cleartext. The first 32 bytes are still the ephemeral public key in the clear, but the remaining bytes are AEAD-encrypted.

## XX — Noise_XX_25519_ChaChaPoly_SHA256

Pattern: `-> e` / `<- e, ee, s, es` / `-> s, se`
Mutual authentication with no prior key knowledge. The workhorse pattern.

```
handshake_hash: c8e5f64e846193be2a834104c2a009868d6c9f3bd3c186299888b488b2f1f58e

Message 1 (-> e):
  payload:    4c756477696720766f6e204d69736573
  ciphertext: ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944
              4c756477696720766f6e204d69736573

Message 2 (<- e, ee, s, es):
  payload:    4d757272617920526f746862617264
  ciphertext: 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843
              81cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b9
              bd5269c2f1e4f488ed8831161f19b7815528f8982ffe09be9b5c412f8a0db50f
              8814c7194e83f23dbd8d162c9326ad

Message 3 (-> s, se):
  payload:    462e20412e20486179656b
  ciphertext: c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a8
              0ae475b9df0f169ae80a89be0865b57f58c9fea0d4ec82a286427402f113e4b6
              ae769a1d95941d49b25030

Transport 1 (responder → initiator):
  payload:    4361726c204d656e676572
  ciphertext: 96763ed773f8e47bb3712f0e29b3060ffc956ffc146cee53d5e1df

Transport 2 (initiator → responder):
  payload:    4a65616e2d426170746973746520536179
  ciphertext: 3e40f15f6f3a46ae446b253bf8b0d9ffb6ed9b174d272328ff91a7e2e5c79c07f5
```

Note: Message 2 is large — it contains `e.public (32)` + encrypted `s (32+16 tag)` + encrypted `payload (+16 tag)`. Message 3 contains encrypted `s (32+16 tag)` + encrypted `payload (+16 tag)`.

## IK — Noise_IK_25519_ChaChaPoly_SHA256

Pattern: `<- s` / `-> e, es, s, ss` / `<- e, ee, se`
Zero-RTT mutual authentication. Initiator knows responder's static key.

```
handshake_hash: 0b0f68fb0c27e03ce9b97565995ed4838cc0581b762ef72b062f6a546419fad7

Message 1 (-> e, es, s, ss):
  payload:    4c756477696720766f6e204d69736573
  ciphertext: ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944
              718da798efbcd91528520204f904b9bd6c7413dccdc214d951e15253e39987f1
              8146e8cd0873654207148333479d4d16c289f0294b29960a72f48e0b7bba2e89
              083169825e59642148d492020664ccf7

Message 2 (<- e, ee, se):
  payload:    4d757272617920526f746862617264
  ciphertext: 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843
              5361e70b2ed446e6c9ec387d1d6b3b840f194e373979d241b203c4acafccf5

Transport 1 (initiator → responder):
  payload:    462e20412e20486179656b
  ciphertext: 050e9f3c8fac16b68dbce8f8c4bfbf6617c897f9ada4aa29aa19c8

Transport 2 (responder → initiator):
  payload:    4361726c204d656e676572
  ciphertext: 344233a6cabb7141d80f3da2fedc311d9646bbb0f505afe403a667
```

Note: Message 1 is the largest — it contains `e.public (32)` + encrypted `s (32+16)` + encrypted `payload (+16)`. This is the Noise Pipes "abbreviated handshake" when it succeeds.

## NKpsk0 — Noise_NKpsk0_25519_ChaChaPoly_SHA256

Pattern: `<- s` / `-> psk, e, es` / `<- e, ee`
NK with a pre-shared key at position 0 — adds quantum resistance to the 0-RTT payload.

```
handshake_hash: 1609ef057bdd62c752b5960546a255a78aebff08c5f07ef2adaa1db8350e7077

Message 1 (-> psk, e, es):
  payload:    4c756477696720766f6e204d69736573
  ciphertext: ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944
              190fec41487219f2069c3ba7b7f9521437045935231f0ed399dfd4baf6bd825b

Message 2 (<- e, ee):
  payload:    4d757272617920526f746862617264
  ciphertext: 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843
              85010e0c56e886e6da0c69aee7388bcf4000cc357af5ebd11a46a169a3712c

Transport 1:
  payload:    462e20412e20486179656b
  ciphertext: 4beed26535f1a387c950fab9a162dc613cc5bf84e8a62653130b83

Transport 2:
  payload:    4361726c204d656e676572
  ciphertext: ceaffe71ce7f1bf7b080736d62e0579ce5dc1530a36e7df795a4cc
```

Note: The `psk` token calls `MixKeyAndHash(psk)` before any DH operations. Compare message 1 ciphertext with plain NK — the encrypted payload bytes differ because the symmetric state includes the PSK.

## IKpsk2 — Noise_IKpsk2_25519_ChaChaPoly_SHA256

Pattern: `<- s` / `-> e, es, s, ss, psk` / `<- e, ee, se`
This is the WireGuard handshake pattern. IK with PSK at position 2.

```
handshake_hash: 8310f86394dc0dabb40beb8210031556db4403ab1202db7034c526232147a700

Message 1 (-> e, es, s, ss, psk):
  payload:    4c756477696720766f6e204d69736573
  ciphertext: ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944
              2ec9b09893d0f510791784c10cbc959f25b1766e0def6e301d14fbca1c7790ac
              829b8b3674f5f649a5f0e98479662cbfbf2b2c47cd4b09fcd266cd29d7cb675f
              1808849707847840f6d178ec4d3733aa

Message 2 (<- e, ee, se):
  payload:    4d757272617920526f746862617264
  ciphertext: 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843
              9a1b3cebf680b2c74217fcb5eba4ff58a9468cd90c4aca6194f57479b379a7

Transport 1:
  payload:    462e20412e20486179656b
  ciphertext: a8fde7a0accec190cd306c5950d4fd8e04a205ec288aa747d8b347

Transport 2:
  payload:    4361726c204d656e676572
  ciphertext: 59caddd9984a3bbe24c4fb31a2bd455b7eba3fa0980674b1a3a5f9
```

Note: Compare with plain IK — the PSK changes the encrypted static and payload bytes but the ephemeral public key prefix is identical (it's sent before any encryption).

## XXfallback — Noise_XXfallback_25519_ChaChaPoly_SHA256

The Noise Pipes fallback: IK fails (wrong server key), falls back to XXfallback. This vector uses a **wrong** `init_remote_static` to trigger the fallback.

```
init_remote_static (WRONG key): f215fe4ad54b354588d3fa52166179b723b9a211ec67167b9bf1729260972a23
resp_static (ACTUAL):           4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893

handshake_hash: ecabd6cfc98cb5d46b2abdc22bf2c3e8dc97e40fc019eff2da912db4f19266c6

Message 1 (IK -> e, es, s, ss — will fail on responder):
  payload:    4c756477696720766f6e204d69736573
  ciphertext: ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944
              a5ee5bed9cfbd66a10caecd9c3d7712389cd8b2b9d6f085cf010d25d4a8efd80
              88e4cf0f017e5421a790b54b870c619834ebc7c2cc0b3e94ccd34041845046332
              081c1bd470deb1197d20a352dedcd80

Message 2 (XXfallback <- e, ee, s, es — responder becomes initiator):
  payload:    4d757272617920526f746862617264
  ciphertext: 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843
              c95caa5acaf9a7cf34254947f0d8da9233b3a4a57993c4d824696e4b1cef496c
              b18dd4f1769969fbb0551ee2d4b6edd0084b2a393fd6abd60235cc1b608d2df2
              10b208d2f0eb8aea090a565d95d91e

Message 3 (XXfallback -> s, se — original initiator sends static):
  payload:    462e20412e20486179656b
  ciphertext: 1ec24f2fa67db6f7335bb7e2848571f4be76ae6702fd2123465e59e6f92f020a
              ec4171e275fc91649d9ebedc91a507ec5bf745ec726d4ff246b6d4f460ac30e6
              b281174289a9ffd34722a8

Transport 1:
  payload:    4361726c204d656e676572
  ciphertext: a5bfb0ca1ccf0e51d4fb1db0b6ca2e4a7d6e8c5f99a855f9acd085
```

### How to process the fallback

1. **Initiator** sends message 1 as a normal IK handshake (using the wrong remote static key)
2. **Responder** attempts to decrypt → AEAD fails (key mismatch)
3. **Responder** extracts the initiator's ephemeral public key from message 1 (first 32 bytes)
4. **Responder** re-initializes as XXfallback initiator, with the extracted ephemeral as the pre-message `-> e`
5. **Roles reverse**: the original responder sends message 2 as the XXfallback initiator
6. **Original initiator** detects fallback, re-initializes as XXfallback responder
7. Message 3 completes the handshake

## Full Vector Sources

The vectors above cover the most common 25519+ChaChaPoly+SHA256 combinations. For comprehensive testing across all DH/cipher/hash combinations (944 vectors total), PSK variants, and fallback patterns:

- **cacophony** (944 vectors, all fundamental + deferred + PSK patterns):
  https://raw.githubusercontent.com/centromere/cacophony/master/vectors/cacophony.txt

- **noise-c-basic** (all fundamental patterns, both DH × cipher × hash combos):
  https://raw.githubusercontent.com/rweather/noise-c/master/tests/vector/noise-c-basic.txt

- **noise-c-fallback** (XXfallback vectors for all cipher suites):
  https://raw.githubusercontent.com/rweather/noise-c/master/tests/vector/noise-c-fallback.txt

- **snow-multipsk** (multi-PSK patterns):
  https://raw.githubusercontent.com/mcginty/snow/master/tests/vectors/snow-multipsk.txt

- **Test vector format specification**:
  https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors
