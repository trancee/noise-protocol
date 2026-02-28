# Noise Protocol Security Properties

## Payload Security Levels

Each payload in a handshake or transport message has a **source** property (authentication) and a **destination** property (confidentiality).

### Source Properties (Authentication)

| Level | Meaning |
|-------|---------|
| **0** | No authentication. Payload may have been sent by any party, including an active attacker. |
| **1** | Authenticated via static-static DH. Sender's static key is known but vulnerable to Key Compromise Impersonation (KCI). If the recipient's static key is compromised, an attacker can impersonate the sender. |
| **2** | Authenticated via ephemeral-static DH. Resistant to KCI — compromising the recipient's key doesn't allow impersonation of the sender. |

### Destination Properties (Confidentiality)

| Level | Meaning |
|-------|---------|
| **0** | No confidentiality. Payload is in cleartext or trivially decryptable. |
| **1** | Encrypted with forward secrecy to an ephemeral recipient. If the recipient's static key is later compromised, this payload remains safe. |
| **2** | Encrypted to a known recipient (static key). Vulnerable if recipient's static key is compromised — no forward secrecy. |
| **3** | Encrypted with weak forward secrecy. Safe if both parties' static keys remain uncompromised; if one ephemeral key leaks, the payload may be decryptable. |
| **4** | Encrypted with weak forward secrecy from sender's perspective. If sender's static key is compromised, forward secrecy degrades. |
| **5** | Strong forward secrecy. Payload protected even if all static keys are later compromised (requires both ephemeral keys). |

## Security Properties per Pattern

### One-Way Patterns

| Pattern | Payload | Source | Destination |
|---------|---------|--------|-------------|
| N | → payload | 0 | 2 |
| K | → payload | 1 | 2 |
| X | → payload | 1 | 2 |

### Interactive Patterns (Payload Security)

| Pattern | Message | Source | Destination |
|---------|---------|--------|-------------|
| **NN** | → 1st | 0 | 0 |
| | ← 2nd | 0 | 1 |
| **NK** | → 1st | 0 | 2 |
| | ← 2nd | 0 | 5 |
| **NX** | → 1st | 0 | 0 |
| | ← 2nd | 0 | 3 |
| **KN** | → 1st | 0 | 0 |
| | ← 2nd | 1 | 1 |
| **KK** | → 1st | 1 | 2 |
| | ← 2nd | 2 | 5 |
| **KX** | → 1st | 0 | 0 |
| | ← 2nd | 1 | 3 |
| **XN** | → 1st | 0 | 0 |
| | ← 2nd | 0 | 1 |
| | → 3rd | 2 | 1 |
| **XK** | → 1st | 0 | 2 |
| | ← 2nd | 0 | 5 |
| | → 3rd | 2 | 5 |
| **XX** | → 1st | 0 | 0 |
| | ← 2nd | 0 | 3 |
| | → 3rd | 2 | 3 |
| **IN** | → 1st | 0 | 0 |
| | ← 2nd | 2 | 1 |
| **IK** | → 1st | 1 | 2 |
| | ← 2nd | 2 | 5 |
| **IX** | → 1st | 0 | 0 |
| | ← 2nd | 2 | 3 |

## Identity-Hiding Properties

Tracks whether static public keys are protected from passive and active attackers.

| Level | Meaning |
|-------|---------|
| **0** | Static key transmitted in cleartext |
| **1** | Encrypted with forward secrecy; active probing can reveal identity |
| **2** | Encrypted with forward secrecy; anonymous recipient (no probing) |
| **3** | Not transmitted; passive key-candidate checking possible |
| **4** | Encrypted without forward secrecy |
| **5** | Not transmitted; KCI-enabled checking possible |
| **6** | Weak forward secrecy against active attackers |
| **7** | Active attacker key-candidate checking |
| **8** | Encrypted with forward secrecy to authenticated party |
| **9** | Active attacker single-run checking |

### Identity Hiding per Pattern

| Pattern | Initiator | Responder |
|---------|-----------|-----------|
| N | — | 3 |
| K | 5 | 5 |
| X | 4 | 3 |
| NN | — | — |
| NK | — | 3 |
| NX | — | 1 |
| KN | 5 | — |
| KK | 5 | 5 |
| KX | 5 | 1 |
| XN | 1 | — |
| XK | 8 | 3 |
| XX | 2 | 1 |
| IN | 0 | — |
| IK | 4 | 3 |
| IX | 0 | 1 |

## Choosing a Pattern

### Use XX when:
- Neither party knows the other's key
- Maximum flexibility needed
- 1-RTT latency acceptable

### Use IK when:
- Initiator knows responder's static key (e.g., server)
- 0-RTT encrypted payload desired
- Willing to fall back (Noise Pipes) on key mismatch

### Use NK when:
- Only responder authentication needed (like TLS with no client cert)
- Initiator is anonymous

### Use KK when:
- Both parties pre-share keys
- Mutual authentication from first message
- 0.5-RTT full security

### Use NN when:
- No authentication needed
- Opportunistic encryption only
- Anonymous channel establishment

### Use N when:
- One-way message to known recipient
- Sender is anonymous
- No response expected

## PSK Impact on Security

Adding PSK modifiers upgrades security properties:
- Provides additional authentication layer independent of DH
- Protects against future quantum attacks on DH (if PSK remains secret)
- PSK at position 0 (`psk0`) authenticates the first message immediately
- PSK must have 256-bit entropy minimum

## Transport Phase Security

After handshake completes, `Split()` produces two CipherStates:
- First CipherState: initiator → responder encryption
- Second CipherState: responder → initiator encryption
- Both have forward secrecy derived from ephemeral DH
- Nonce-based AEAD prevents replay within a session
- `Rekey()` enables periodic key rotation without new handshake
