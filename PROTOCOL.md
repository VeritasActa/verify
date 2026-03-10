# BRASS Protocol Specification

> **Version:** 2.0
> **Cipher suite:** P256_SHA256
> **Status:** Patent pending

## Overview

BRASS (Blind Rate-limiting with Anonymous Scope Separation) is a privacy-preserving rate-limiting protocol built on Verifiable Oblivious Pseudorandom Functions (VOPRF, [RFC 9497](https://datatracker.ietf.org/doc/html/rfc9497)).

The protocol separates token issuance from token verification, with a mathematical guarantee that the issuer cannot learn where tokens are redeemed. The verifier enforces per-scope rate limits using deterministic nullifiers derived from service-side context that the client cannot influence.

## Notation

| Symbol | Meaning |
|--------|---------|
| G | P-256 base point (generator) |
| k | Issuer private key (scalar) |
| Y | Issuer public key Y = k·G |
| P | Scope point P = H1(scope) |
| M | Blinded message M = r·P |
| Z | Issuer evaluation Z = k·M |
| Z' | Unblinded token Z' = r⁻¹·Z = k·P |
| r | Client blinding factor (random scalar) |
| η | Verifier-derived salt |
| y | Deterministic nullifier |
| τ | Per-scope rate limit threshold |
| W | Window identifier |
| πI | Issuer DLEQ proof |
| πC | Client DLEQ proof |
| c | Verifier-issued nonce |
| d | HTTP context digest |
| KID | Issuer key identifier |
| AADr | Associated data at redemption |

## Protocol flow

### Phase 1: Issuance (client ↔ issuer)

```
1. Client generates random blinding factor r ∈ Z*_n
2. Client computes P = H1(scope) for their target scope
3. Client computes M = r · P (blinded message)
4. Client sends M to issuer
5. Issuer computes Z = k · M
6. Issuer generates DLEQ proof πI: log_G(Y) = log_M(Z)
7. Issuer returns (Z, πI) to client
8. Client unblinds: Z' = r⁻¹ · Z = k · P
```

The issuer learns M but not P (because M = r·P and r is random). The issuer cannot determine which scope the token is for.

### Phase 2: Redemption (client → verifier)

```
1. Client sends redemption message:
   (M, Z, Z', P, πI, πC, c_nonce, d, AADr)

2. Verifier derives scope from HTTP transport context:
   origin = canonicalOrigin(request.origin)
   epoch = floor(now / 86400000)
   policy = parsePolicyId(AADr)
   W = windowId(now, windowSec)

3. Verifier derives salt (client cannot influence):
   η = H3('BRASS_SALT_v1', IssuerPK, Origin, Epoch, Policy, W [, VerifierSecret])

4. Verifier validates all P-256 points (M, Z, Z', Y)

5. Verifier checks issuer proof πI:
   Verify DLEQ: log_G(Y) = log_M(Z)
   → Confirms Z was computed by holder of k

6. Verifier checks client proof πC:
   bindContext = H3(c_nonce, d, η, tlsBinding)
   Verify DLEQ: log_P(M) = log_{Z'}(Z)
   → Confirms client knows blinding factor r, bound to nonce

7. Verifier derives nullifier:
   y = H2('BRASS_NULLIFIER_v1', enc(Z'), KID, AADr, η)

8. Verifier counts:
   if count(y) < τ: accept, increment
   else: reject (429)
```

## Cryptographic functions

### H3: Domain-separated hash

```
H3(part₁, part₂, ..., partₙ) =
  SHA-256(lenprefix(bytes(part₁)) ‖ lenprefix(bytes(part₂)) ‖ ... ‖ lenprefix(bytes(partₙ)))

where:
  bytes(s: string) = UTF-8(s)
  bytes(n: number) = BigEndian32(n)
  bytes(b: Uint8Array) = b
  lenprefix(b) = BigEndian32(len(b)) ‖ b
```

Length-prefixing prevents cross-field collisions: `H3("ab", "c") ≠ H3("a", "bc")`.

### H2: Nullifier hash

`H2 = H3` (identical implementation; separate name for protocol clarity).

### Salt derivation (η)

```
η = H3('BRASS_SALT_v1',
        UTF-8(IssuerPK_b64),
        UTF-8(OriginCanonical),
        UTF-8(Epoch),
        UTF-8(PolicyID),
        UTF-8(WindowID)
        [, VerifierSecret])
```

The optional `VerifierSecret` prevents precomputation attacks and cross-verifier collisions.

### Nullifier derivation (y)

```
y = H2('BRASS_NULLIFIER_v1',
        UTF-8(enc(Z')),
        UTF-8(KID),
        UTF-8(AADr),
        η)
```

Properties:
- **Deterministic**: Same (Z', scope, window) → same y
- **Unlinkable across windows**: Different W → different η → different y
- **Unlinkable across origins**: Different Origin → different η → different y
- **Client cannot influence**: η is derived from server-side context only

### Idempotency key (IK)

```
IK = HMAC-SHA256(kvSecret, lenprefix(y) ‖ lenprefix(decode_b64(c_nonce)))
```

Prevents double-counting of the same (token, nonce) pair.

### Grace-bridge nullifier

```
y_grace = H2('BRASS_GRACE_v2',
              enc(Z'), KID, IssuerPK, Origin, PolicyID,
              CipherSuite, ProtocolVersion, AADr)
```

Window-agnostic nullifier used during grace periods around window boundaries. Prevents double-spend across the W → W+1 transition.

## DLEQ proof verification

Both πI and πC use Schnorr-style DLEQ proofs:

```
Prove: log_{g1}(h1) = log_{g2}(h2)

Prover (knows secret s):
  1. r ← random scalar
  2. A1 = r · g1
  3. A2 = r · g2
  4. c = H3('BRASS:label:', g1, h1, g2, h2, A1, A2, bind) mod n
  5. z = r - c·s mod n
  6. Output (A1, A2, c, z)

Verifier:
  1. Recompute c' = H3('BRASS:label:', g1, h1, g2, h2, A1, A2, bind) mod n
  2. Accept if c' = c
```

### πI (Issuer proof)

| Parameter | Value |
|-----------|-------|
| g1 | G (P-256 base point) |
| h1 | Y (issuer public key) |
| g2 | M (blinded message) |
| h2 | Z (issuer evaluation) |
| bind | AADr |
| label | `OPRF_METERING_DLEQ_v1` |

Proves the issuer applied the same key k to both G (producing Y) and M (producing Z).

### πC (Client proof)

| Parameter | Value |
|-----------|-------|
| g1 | P (scope point) |
| h1 | M (blinded message) |
| g2 | Z' (unblinded token) |
| h2 | Z (issuer evaluation) |
| bind | H3(c_nonce, d, η, tlsBinding) |
| label | `OPRF_METERING_DLEQ_v1` |

Proves the client knows the blinding factor r such that M = r·P, bound to a fresh nonce. Prevents token theft — a stolen (Z, Z') is useless without r.

## Origin canonicalization

```
canonicalOrigin("https://Example.COM:443/path?q=1") → ERROR (has path)
canonicalOrigin("https://Example.COM:443")          → "https://example.com"
canonicalOrigin("https://Example.COM:8443")          → "https://example.com:8443"
canonicalOrigin("http://example.com")                → ERROR (not HTTPS)
```

Rules:
- HTTPS only
- No path, query, or fragment
- Lowercase hostname
- IDNA normalization (punycode)
- Default port 443 elided
- Trailing dots stripped

## Window management

### Window ID

```
W = floor(nowMs / (windowSec × 1000))
```

Default `windowSec = 86400` gives day-level windows. Set to 3600 for hourly, 60 for per-minute.

### Clock skew tolerance

Within 30 seconds of a window boundary, the verifier accepts tokens from both the current and previous window:

```
validWindows(nowMs, windowSec):
  current = floor(nowMs / windowMs)
  windows = [current]
  if (nowMs % windowMs) < 30000:
    windows.push(current - 1)
  return windows
```

### Grace-bridge protection

During the grace period (default: 60 seconds before and after each window boundary), the verifier uses a window-agnostic nullifier to prevent double-spend:

```
isInGracePeriod(nowMs, graceSeconds, windowSec):
  graceMs = graceSeconds × 1000
  windowMs = windowSec × 1000
  msIntoWindow = nowMs % windowMs
  return msIntoWindow < graceMs OR msIntoWindow > (windowMs - graceMs)
```

Grace flow:
1. Check grace cache for `y_grace` → if HIT, return cached response
2. Process normal verification with window-specific y
3. Cache response under `y_grace` with TTL = 2 × graceSeconds

## TLS channel binding

When TLS exporter bytes are available ([RFC 5705](https://datatracker.ietf.org/doc/html/rfc5705)/[8446](https://datatracker.ietf.org/doc/html/rfc8446)):

```
tlsBinding = H3('tls_exporter', exporterBytes)
```

Fallback (development, proxied):

```
tlsBinding = H3('no_exporter')
```

Domain separation prevents collision between the two modes.

## Security properties

| Property | Guarantee | Mechanism |
|----------|-----------|-----------|
| **Issuer blindness** | Issuer cannot learn redemption scope | M = r·P hides P; issuer never sees η or y |
| **Unlinkability** | Different windows/scopes produce different nullifiers | η includes (Origin, Window, Policy) |
| **Replay protection** | Same (token, nonce) pair counted at most once | Idempotency key IK = HMAC(secret, y, nonce) |
| **Token binding** | Stolen tokens are useless without blinding factor | πC proves knowledge of r, bound to fresh nonce |
| **Boundary protection** | No double-spend across window transitions | Grace-bridge nullifier during ±graceSeconds |
| **Forge resistance** | Cannot create valid tokens without issuer key k | πI proves Z = k·M |
| **Deterministic counting** | Same anonymous user counted consistently within scope | y = f(Z', scope, η) is deterministic |

## Threat model

**In scope:**
- Malicious clients attempting to evade rate limits
- Token theft (mitigated by πC binding to r and nonce)
- Cross-window replay (mitigated by grace-bridge)
- Origin bypass via URL manipulation (mitigated by canonicalization)
- Precomputation of η (mitigated by optional verifierSecret)

**Out of scope:**
- Compromised issuer key k (requires key rotation)
- Side-channel attacks on the verifier process
- Denial of service (rate limiting the rate limiter)

## Storage backend requirements

Implementations of `BrassCounterStore` must provide:

1. **Idempotency**: Same `idempotencyKey` returns cached result, does not re-increment
2. **Threshold enforcement**: Reject when `count ≥ limit`
3. **TTL expiry**: Counters and IK entries expire after `ttlSeconds`
4. **Grace guard** (optional): Check-and-cache for grace-bridge nullifiers

Consistency guarantees vary by backend:
- **Strongly consistent** (Durable Objects, Redis with WATCH): Zero overspend
- **Eventually consistent** (KV, DynamoDB): Bounded overspend ≤ (E-1)·λ·w

## References

- [RFC 9497 — VOPRF](https://datatracker.ietf.org/doc/html/rfc9497)
- [RFC 9380 — Hashing to Elliptic Curves](https://datatracker.ietf.org/doc/html/rfc9380)
- [RFC 9449 — DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
- [RFC 5705 — TLS Keying Material Exporters](https://datatracker.ietf.org/doc/html/rfc5705)
- [@noble/curves](https://github.com/paulmillr/noble-curves) — Audited P-256 implementation
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) — Audited SHA-256/HMAC
