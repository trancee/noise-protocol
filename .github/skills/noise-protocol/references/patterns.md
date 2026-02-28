# Noise Handshake Patterns — Complete Reference

## Pre-Message Patterns

Pre-messages represent keys exchanged before the handshake begins. They are hashed into `h` during initialization but not transmitted.

Valid pre-message patterns:
- (empty)
- `e`
- `s`
- `e, s`

## One-Way Patterns

### N — Anonymous sender to known recipient
```
<- s
...
-> e, es
```
Sender has no static key. Recipient's static key is pre-known.

### K — Known sender to known recipient
```
-> s
<- s
...
-> e, es, ss
```
Both static keys pre-exchanged.

### X — Sender transmits identity encrypted
```
<- s
...
-> e, es, s, ss
```
Recipient's key pre-known. Sender's key transmitted encrypted.

## Interactive Patterns — Fundamental

### NN — No authentication
```
-> e
<- e, ee
```
Ephemeral-only. Vulnerable to MITM. Useful for anonymous channels.

### NK — Responder pre-known
```
<- s
...
-> e, es
<- e, ee
```
Initiator knows responder's static key. No initiator authentication.

### NX — Responder sends certificate
```
-> e
<- e, ee, s, es
```
Responder transmits static key encrypted. No initiator authentication.

### KN — Initiator pre-known
```
-> s
...
-> e
<- e, ee, se
```
Responder knows initiator's static key. No responder authentication.

### KK — Mutual pre-knowledge
```
-> s
<- s
...
-> e, es, ss
<- e, ee, se
```
Both parties know each other's static keys beforehand.

### KX — Initiator known, responder sends certificate
```
-> s
...
-> e
<- e, ee, se, s, es
```

### XN — Initiator sends certificate, no responder auth
```
-> e
<- e, ee
-> s, se
```

### XK — Initiator sends certificate, responder pre-known
```
<- s
...
-> e, es
<- e, ee
-> s, se
```

### XX — Mutual certificate exchange
```
-> e
<- e, ee, s, es
-> s, se
```
Most flexible pattern. Both parties learn each other's identity.

### IN — Initiator immediately identified, no responder auth
```
-> e, s
<- e, ee, se
```
Less identity hiding for initiator than X patterns.

### IK — Zero-RTT to known responder
```
<- s
...
-> e, es, s, ss
<- e, ee, se
```
Initiator sends encrypted payload in first message. Widely used (e.g., WireGuard-like).

### IX — Initiator immediately identified, responder sends certificate
```
-> e, s
<- e, ee, se, s, es
```

## Deferred Patterns

Deferred patterns use a `1` suffix to move authentication DH operations to later messages. This improves identity hiding and enables future substitution of DH with signatures or KEMs.

### NK1
```
<- s
...
-> e
<- e, ee, es
```
Defers `es` from message 1 to message 2.

### NX1
```
-> e
<- e, ee, s
-> es
```
Defers `es` from message 2 to message 3.

### X1N
```
-> e
<- e, ee
-> s
<- se
```

### X1K
```
<- s
...
-> e, es
<- e, ee
-> s
<- se
```

### XK1
```
<- s
...
-> e
<- e, ee, es
-> s, se
```

### X1K1
```
<- s
...
-> e
<- e, ee, es
-> s
<- se
```

### X1X
```
-> e
<- e, ee, s, es
-> s
<- se
```

### XX1
```
-> e
<- e, ee, s
-> es, s, se
```

### X1X1
```
-> e
<- e, ee, s
-> es, s
<- se
```

### K1N
```
-> s
...
-> e
<- e, ee
-> se (error: should be from responder)
```

### K1K
```
-> s
<- s
...
-> e, es
<- e, ee
-> se (deferred)
```

### KK1
```
-> s
<- s
...
-> e
<- e, ee, se, es
```

### K1K1
```
-> s
<- s
...
-> e
<- e, ee, es
-> se
```

### K1X
```
-> s
...
-> e
<- e, ee, s, es
-> se
```

### KX1
```
-> s
...
-> e
<- e, ee, se, s
-> es
```

### K1X1
```
-> s
...
-> e
<- e, ee, s
-> se, es
```

### I1N
```
-> e, s
<- e, ee
-> se (deferred)
```

### I1K
```
<- s
...
-> e, es, s
<- e, ee
-> se (deferred)
```

### IK1
```
<- s
...
-> e, s
<- e, ee, se, es
```

### I1K1
```
<- s
...
-> e, s
<- e, ee, es
-> se
```

### I1X
```
-> e, s
<- e, ee, s, es
-> se
```

### IX1
```
-> e, s
<- e, ee, se, s
-> es
```

### I1X1
```
-> e, s
<- e, ee, s
-> se, es
```

## Compound Protocol Patterns

### Fallback Modifier

Converts an initiator-started pattern to a responder-started one by moving the initiator's first message tokens to a pre-message.

**XX → XXfallback:**
```
-> e        (becomes pre-message)
...
<- e, ee, s, es
-> s, se
```

### Noise Pipes (IK + XXfallback)

Phase 1 — Try IK:
```
<- s
...
-> e, es, s, ss    (with encrypted payload)
<- e, ee, se
```

Phase 2 — On failure, switch to XXfallback:
```
-> e               (re-use from IK attempt)
...
<- e, ee, s, es
-> s, se
```

Both phases share the initiator's ephemeral key. The responder detects IK failure (e.g., wrong static key) and initiates fallback.
