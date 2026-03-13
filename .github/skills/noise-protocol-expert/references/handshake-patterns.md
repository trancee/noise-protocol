# Handshake Patterns Reference

## Table of Contents
1. [One-way patterns](#one-way-patterns)
2. [Fundamental interactive patterns](#fundamental-interactive-patterns)
3. [Deferred interactive patterns](#deferred-interactive-patterns)
4. [Security properties table](#security-properties-table)
5. [Deferred pattern security properties](#deferred-pattern-security-properties)
6. [Identity hiding properties](#identity-hiding-properties)
7. [Pattern derivation rules](#pattern-derivation-rules)

---

## One-way patterns

One-way patterns support a one-way stream of data from sender to recipient. After the handshake, the sender encrypts transport messages using the first CipherState from `Split()`. The second CipherState is discarded.

Named with a single character indicating the sender's static key status:
- **N** = No static key for sender
- **K** = Static key Known to recipient
- **X** = Static key Xmitted (transmitted) to recipient

```
N:
  <- s
  ...
  -> e, es
```

```
K:
  -> s
  <- s
  ...
  -> e, es, ss
```

```
X:
  <- s
  ...
  -> e, es, s, ss
```

- `N` is conventional DH-based public-key encryption.
- `K` and `X` add sender authentication — `K` when the recipient already knows the sender's key, `X` when it's transmitted (encrypted) during the handshake.

---

## Fundamental interactive patterns

12 fundamental patterns. Named with two characters: first = initiator's static key, second = responder's static key.

**First character (initiator):** N, K, X, I
**Second character (responder):** N, K, X

"I" (Immediately) means the initiator transmits their static key in the first message (reduced identity hiding compared to X).

```
NN:                         KN:
  -> e                        -> s
  <- e, ee                    ...
                              -> e
                              <- e, ee, se
```

```
NK:                         KK:
  <- s                        -> s
  ...                         <- s
  -> e, es                    ...
  <- e, ee                    -> e, es, ss
                              <- e, ee, se
```

```
NX:                         KX:
  -> e                        -> s
  <- e, ee, s, es             ...
                              -> e
                              <- e, ee, se, s, es
```

```
XN:                         IN:
  -> e                        -> e, s
  <- e, ee                    <- e, ee, se
  -> s, se
```

```
XK:                         IK:
  <- s                        <- s
  ...                         ...
  -> e, es                    -> e, es, s, ss
  <- e, ee                    <- e, ee, se
  -> s, se
```

```
XX:                         IX:
  -> e                        -> e, s
  <- e, ee, s, es             <- e, ee, se, s, es
  -> s, se
```

### Pattern selection summary

- **XX** is the most generically useful (mutual auth, both keys transmitted encrypted).
- Patterns ending in K allow zero-RTT encryption.
- Patterns starting with K or I allow half-RTT encryption targeting the initiator's static key.
- I patterns trade identity hiding for fewer round trips compared to X patterns.

---

## Deferred interactive patterns

Deferred patterns append `1` after the first and/or second character to indicate the initiator's and/or responder's authentication DH is deferred to the next message.

Full set of 23 deferred patterns:

```
NK1:                        NX1:
  <- s                        -> e
  ...                         <- e, ee, s
  -> e                        -> es
  <- e, ee, es
```

```
X1N:                        X1K:
  -> e                        <- s
  <- e, ee                    ...
  -> s                        -> e, es
  <- se                       <- e, ee
                              -> s
                              <- se
```

```
XK1:                        X1K1:
  <- s                        <- s
  ...                         ...
  -> e                        -> e
  <- e, ee, es                <- e, ee, es
  -> s, se                    -> s
                              <- se
```

```
X1X:                        XX1:
  -> e                        -> e
  <- e, ee, s, es             <- e, ee, s
  -> s                        -> es, s, se
  <- se
```

```
X1X1:                       K1N:
  -> e                        -> s
  <- e, ee, s                 ...
  -> es, s                    -> e
  <- se                       <- e, ee
                              -> se
```

```
K1K:                        KK1:
  -> s                        -> s
  <- s                        <- s
  ...                         ...
  -> e, es                    -> e
  <- e, ee                    <- e, ee, se, es
  -> se
```

```
K1K1:                       K1X:
  -> s                        -> s
  <- s                        ...
  ...                         -> e
  -> e                        <- e, ee, s, es
  <- e, ee, es                -> se
  -> se
```

```
KX1:                        K1X1:
  -> s                        -> s
  ...                         ...
  -> e                        -> e
  <- e, ee, se, s             <- e, ee, s
  -> es                       -> se, es
```

```
I1N:                        I1K:
  -> e, s                     <- s
  <- e, ee                    ...
  -> se                       -> e, es, s
                              <- e, ee
                              -> se
```

```
IK1:                        I1K1:
  <- s                        <- s
  ...                         ...
  -> e, s                     -> e, s
  <- e, ee, se, es            <- e, ee, es
                              -> se
```

```
I1X:                        IX1:
  -> e, s                     -> e, s
  <- e, ee, s, es             <- e, ee, se, s
  -> se                       -> es
```

```
I1X1:
  -> e, s
  <- e, ee, s
  -> se, es
```

---

## Security properties table

Each payload is assigned source (authentication) and destination (confidentiality) properties.

### Source properties
- **0** = No authentication
- **1** = Sender auth vulnerable to KCI (based on `ss` DH)
- **2** = Sender auth resistant to KCI (based on `es`/`se` DH)

### Destination properties
- **0** = Cleartext
- **1** = Encrypted to ephemeral (forward secret, unauthenticated recipient)
- **2** = Encrypted to known recipient (no forward secrecy, replayable)
- **3** = Weak forward secrecy
- **4** = Weak forward secrecy if sender compromised
- **5** = Strong forward secrecy

### One-way patterns

| Pattern | Source | Destination |
|---------|--------|-------------|
| N | 0 | 2 |
| K | 1 | 2 |
| X | 1 | 2 |

### Fundamental interactive patterns

Transport payloads shown as arrows without a pattern. Only listed if different from previous same-direction payload.

```
NN:
  -> e                      0    0
  <- e, ee                  0    1
  ->                        0    1

NK:
  <- s ...
  -> e, es                  0    2
  <- e, ee                  2    1
  ->                        0    5

NX:
  -> e                      0    0
  <- e, ee, s, es           2    1
  ->                        0    5

XN:
  -> e                      0    0
  <- e, ee                  0    1
  -> s, se                  2    1
  <-                        0    5

XK:
  <- s ...
  -> e, es                  0    2
  <- e, ee                  2    1
  -> s, se                  2    5
  <-                        2    5

XX:
  -> e                      0    0
  <- e, ee, s, es           2    1
  -> s, se                  2    5
  <-                        2    5

KN:
  -> s ...
  -> e                      0    0
  <- e, ee, se              0    3
  ->                        2    1
  <-                        0    5

KK:
  -> s <- s ...
  -> e, es, ss              1    2
  <- e, ee, se              2    4
  ->                        2    5
  <-                        2    5

KX:
  -> s ...
  -> e                      0    0
  <- e, ee, se, s, es       2    3
  ->                        2    5
  <-                        2    5

IN:
  -> e, s                   0    0
  <- e, ee, se              0    3
  ->                        2    1
  <-                        0    5

IK:
  <- s ...
  -> e, es, s, ss           1    2
  <- e, ee, se              2    4
  ->                        2    5
  <-                        2    5

IX:
  -> e, s                   0    0
  <- e, ee, se, s, es       2    3
  ->                        2    5
  <-                        2    5
```

### Forward secrecy caveat for K/I patterns

Patterns starting with K or I have a caveat: the responder only has "weak" forward secrecy for transport messages it sends until it receives a transport message from the initiator. After receiving one, strong forward secrecy is established.

---

## Deferred pattern security properties

```
NK1:
  -> e                      0    0
  <- e, ee, es              2    1
  ->                        0    5

NX1:
  -> e                      0    0
  <- e, ee, s               0    1
  -> es                     0    3
  ->                        2    1
  <-                        0    5

X1N:
  -> e                      0    0
  <- e, ee                  0    1
  -> s                      0    1
  <- se                     0    3
  ->                        2    1

X1K:
  -> e, es                  0    2
  <- e, ee                  2    1
  -> s                      0    5
  <- se                     2    3
  ->                        2    5
  <-                        2    5

XK1:
  -> e                      0    0
  <- e, ee, es              2    1
  -> s, se                  2    5
  <-                        2    5

X1K1:
  -> e                      0    0
  <- e, ee, es              2    1
  -> s                      0    5
  <- se                     2    3
  ->                        2    5
  <-                        2    5

X1X:
  -> e                      0    0
  <- e, ee, s, es           2    1
  -> s                      0    5
  <- se                     2    3
  ->                        2    5
  <-                        2    5

XX1:
  -> e                      0    0
  <- e, ee, s               0    1
  -> es, s, se              2    3
  <-                        2    5
  ->                        2    5

X1X1:
  -> e                      0    0
  <- e, ee, s               0    1
  -> es, s                  0    3
  <- se                     2    3
  ->                        2    5
  <-                        2    5

K1N:
  -> s ...
  -> e                      0    0
  <- e, ee                  0    1
  -> se                     2    1
  <-                        0    5

K1K:
  -> s <- s ...
  -> e, es                  0    2
  <- e, ee                  2    1
  -> se                     2    5
  <-                        2    5

KK1:
  -> s <- s ...
  -> e                      0    0
  <- e, ee, se, es          2    3
  ->                        2    5
  <-                        2    5

K1K1:
  -> s <- s ...
  -> e                      0    0
  <- e, ee, es              2    1
  -> se                     2    5
  <-                        2    5

K1X:
  -> s ...
  -> e                      0    0
  <- e, ee, s, es           2    1
  -> se                     2    5
  <-                        2    5

KX1:
  -> s ...
  -> e                      0    0
  <- e, ee, se, s           0    3
  -> es                     2    3
  <-                        2    5
  ->                        2    5

K1X1:
  -> s ...
  -> e                      0    0
  <- e, ee, s               0    1
  -> se, es                 2    3
  <-                        2    5
  ->                        2    5

I1N:
  -> e, s                   0    0
  <- e, ee                  0    1
  -> se                     2    1
  <-                        0    5

I1K:
  <- s ...
  -> e, es, s               0    2
  <- e, ee                  2    1
  -> se                     2    5
  <-                        2    5

IK1:
  <- s ...
  -> e, s                   0    0
  <- e, ee, se, es          2    3
  ->                        2    5
  <-                        2    5

I1K1:
  <- s ...
  -> e, s                   0    0
  <- e, ee, es              2    1
  -> se                     2    5
  <-                        2    5

I1X:
  -> e, s                   0    0
  <- e, ee, s, es           2    1
  -> se                     2    5
  <-                        2    5

IX1:
  -> e, s                   0    0
  <- e, ee, se, s           0    3
  -> es                     2    3
  <-                        2    5
  ->                        2    5

I1X1:
  -> e, s                   0    0
  <- e, ee, s               0    1
  -> se, es                 2    3
  <-                        2    5
  ->                        2    5
```

---

## Identity hiding properties

Properties for each party's static public key:

- **0** = Transmitted in clear
- **1** = Encrypted with forward secrecy, but can be probed by anonymous initiator
- **2** = Encrypted with forward secrecy, but sent to anonymous responder
- **3** = Not transmitted, but passive attacker can check candidates for responder's private key; can also detect if two responders use the same key via replay
- **4** = Encrypted to responder's static key (no forward secrecy)
- **5** = Not transmitted, but passive attacker can check candidate pairs of (responder private, initiator public)
- **6** = Encrypted but with weak forward secrecy (active attacker impersonates initiator, later learns initiator private key)
- **7** = Not transmitted, but active attacker who impersonates initiator then later learns candidate initiator private key can check the candidate
- **8** = Encrypted with forward secrecy to authenticated party
- **9** = Active attacker who impersonates initiator and records a protocol run can check candidates for responder's public key

| Pattern | Initiator | Responder |
|---------|-----------|-----------|
| N | - | 3 |
| K | 5 | 5 |
| X | 4 | 3 |
| NN | - | - |
| NK | - | 3 |
| NK1 | - | 9 |
| NX | - | 1 |
| XN | 2 | - |
| XK | 8 | 3 |
| XK1 | 8 | 9 |
| XX | 8 | 1 |
| KN | 7 | - |
| KK | 5 | 5 |
| KX | 7 | 6 |
| IN | 0 | - |
| IK | 4 | 3 |
| IK1 | 0 | 9 |
| IX | 0 | 6 |

---

## Pattern derivation rules

Rules for deriving one-way, fundamental, and deferred patterns from a pattern name.

**Setup:** Populate pre-message contents as defined by the pattern name.

**Process:** Apply the first matching rule from the table below, delete it, repeat until no rules match. For interactive patterns, alternate between initiator and responder messages.

### Initiator rules (in order)
1. Send `"e"`
2. Perform `"ee"` if `"e"` has been sent and received
3. Perform `"se"` if `"s"` sent and `"e"` received. If initiator auth is deferred, skip first time, then mark as non-deferred
4. Perform `"es"` if `"e"` sent and `"s"` received. If responder auth is deferred, skip first time, then mark as non-deferred
5. Perform `"ss"` if `"s"` sent and received, and `"es"` performed, and this is the first message, and initiator auth is not deferred
6. Send `"s"` if this is the first message and initiator is "I" or one-way "X"
7. Send `"s"` if this is not the first message and initiator is "X"

### Responder rules (in order)
1. Send `"e"`
2. Perform `"ee"` if `"e"` sent and received
3. Perform `"se"` if `"e"` sent and `"s"` received. If initiator auth deferred, skip first time, then mark as non-deferred
4. Perform `"es"` if `"s"` sent and `"e"` received. If responder auth deferred, skip first time, then mark as non-deferred
5. Send `"s"` if responder is "X"
