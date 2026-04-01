# @veritasacta/verify

Anonymous credential verification using VOPRF ([RFC 9497](https://datatracker.ietf.org/doc/html/rfc9497)).

**Issuer-blind. Offline. Deterministic.**

```
npm install @veritasacta/verify
```

Part of the [Veritas Acta](https://github.com/VeritasActa) project — primitives for trust, verification, and privacy.

## What is this?

`@veritasacta/verify` is the verifier-side implementation of the BRASS protocol — a privacy-preserving rate-limiting system that lets you count anonymous requests without learning who is making them.

**Key properties:**

- **Issuer-blind**: The entity issuing tokens never learns which API they're used on
- **Offline verification**: The issuer is never contacted during token redemption
- **Deterministic nullifiers**: Same token + same scope = same nullifier. Different scope = unlinkable
- **Pluggable storage**: Bring your own counter backend (KV, Redis, DynamoDB, in-memory)
- **Zero dependencies** beyond `@noble/curves` and `@noble/hashes` (audited, pure JS)

## How it works

```
  Client                        Issuer                        Verifier (you)
    |                             |                               |
    |-- blind(M) ---------------→|                               |
    |                             |-- Z = k·M, πI              |
    |←--- (Z, πI) ---------------|                               |
    |                             |     (issuer never contacted   |
    |                             |      during verification)     |
    |                                                             |
    |-- (M, Z, Z', πI, πC, nonce) ----------------------------→|
    |                                                             |-- derive η from scope
    |                                                             |-- verify πI (offline)
    |                                                             |-- verify πC (bound to nonce)
    |                                                             |-- y = nullifier(Z', η)
    |                                                             |-- count(y) < threshold?
    |←--- { ok: true, remaining: 94 } ---------------------------|
```

1. Client blinds a request and sends it to the issuer
2. Issuer evaluates the VOPRF and returns a signed token (without learning the scope)
3. Client redeems the token at the verifier with a fresh proof
4. Verifier derives a deterministic nullifier and counts against a per-scope threshold
5. Same token at the same scope = same nullifier (prevents double-spend)
6. Different scope or different window = different nullifier (preserves privacy)

## Quick start

### Express / Node.js

```javascript
import { verify, b64urlToBytes } from '@veritasacta/verify';
import { MemoryStore } from '@veritasacta/verify/adapters/memory';

const store = new MemoryStore();
const config = {
  issuerPubKey: process.env.ISSUER_PUB_KEY,  // base64url P-256 compressed point
  keyId: 'kid-001',
  kvSecret: b64urlToBytes(process.env.KV_SECRET),  // 32-byte secret
  rateLimit: 100,       // requests per window
  windowSec: 86400,     // 1 day
  graceSeconds: 60,     // boundary protection
};

app.post('/api/action', async (req, res) => {
  const msg = JSON.parse(req.headers['x-brass-proof']);
  const ctx = { origin: `https://${req.hostname}` };

  const result = await verify(msg, ctx, config, store);

  if (!result.ok) {
    return res.status(result.error === 'rate_limited' ? 429 : 403).json(result);
  }

  res.setHeader('X-Brass-Remaining', result.remaining);
  // ... handle request
});
```

### Cloudflare Workers

```javascript
import { verify, b64urlToBytes } from '@veritasacta/verify';
import { KVStore } from '@veritasacta/verify/adapters/kv';

export default {
  async fetch(request, env) {
    const msg = await request.json();
    const store = new KVStore(env.BRASS_KV);
    const config = {
      issuerPubKey: env.ISSUER_PUB_KEY,
      keyId: env.KEY_ID,
      kvSecret: b64urlToBytes(env.KV_SECRET),
    };
    const ctx = { origin: request.headers.get('Origin') };

    return Response.json(await verify(msg, ctx, config, store));
  },
};
```

## API

### `verify(msg, ctx, config, store) → Promise<Result>`

Core verification function. Implements the complete redemption flow.

**Parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `msg` | `RedemptionMessage` | Token + proofs from client |
| `ctx` | `RequestContext` | HTTP context (origin, method, path) |
| `config` | `VerifyConfig` | Verifier configuration |
| `store` | `BrassCounterStore` | Pluggable counter backend |

**Result:**

```typescript
{ ok: true, remaining: number }              // Accepted
{ ok: false, error: 'rate_limited', remaining: 0 }  // Over threshold
{ ok: false, error: 'invalid_piI' }          // Bad issuer proof
{ ok: false, error: 'invalid_piC' }          // Bad client proof
{ ok: false, error: 'invalid_origin' }       // Malformed origin
{ ok: false, error: 'invalid_point' }        // Bad EC point encoding
```

### `VerifyConfig`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `issuerPubKey` | `string` | required | Issuer public key Y = k·G (base64url, compressed P-256) |
| `keyId` | `string` | required | Issuer key identifier (KID) |
| `kvSecret` | `Uint8Array` | required | 32-byte secret for idempotency keys |
| `verifierSecret` | `Uint8Array?` | `null` | Per-verifier salt hardening (recommended) |
| `rateLimit` | `number` | `100` | Per-scope threshold (τ) |
| `windowSec` | `number` | `86400` | Window duration in seconds |
| `graceSeconds` | `number` | `60` | Grace period around window boundaries |
| `protocolVersion` | `string` | `'BRASS_v2.0'` | Protocol version |
| `cipherSuite` | `string` | `'P256_SHA256'` | Cipher suite |

### `RedemptionMessage`

| Field | Type | Description |
|-------|------|-------------|
| `M` | `string` | Blinded element (base64url, compressed P-256) |
| `Z` | `string` | Issuer evaluation Z = k·M (base64url) |
| `Zprime` | `string` | Unblinded token Z' = k·P (base64url) |
| `P` | `string?` | Scope point (optional, verifier can reconstruct) |
| `piI` | `object` | Issuer DLEQ proof `{A1, A2, c, r}` |
| `piC` | `object` | Client DLEQ proof `{A1, A2, c, r}` bound to nonce |
| `c_nonce` | `string` | Verifier-issued nonce (base64url) |
| `d` | `string?` | HTTP context digest (base64url) |
| `AADr` | `string` | Associated data at redemption |

## Storage adapters

### MemoryStore (testing / single-process)

```javascript
import { MemoryStore } from '@veritasacta/verify/adapters/memory';
const store = new MemoryStore();
```

In-process Map-based storage. Automatic TTL expiry. Not suitable for distributed deployments.

### KVStore (Cloudflare Workers KV)

```javascript
import { KVStore } from '@veritasacta/verify/adapters/kv';
const store = new KVStore(env.BRASS_KV);
```

Eventually consistent. Free tier: 100K reads/day. Overspend bounded by `(E-1)·λ·w` where E = edge count, λ = per-edge rate, w = replication lag.

### Custom stores

Extend `BrassCounterStore` and implement `spend()`:

```javascript
import { BrassCounterStore } from '@veritasacta/verify/storage';

class RedisStore extends BrassCounterStore {
  async spend({ counterKey, idempotencyKey, limit, ttlSeconds }) {
    // 1. Check idempotency key
    // 2. Increment counter atomically
    // 3. Return { ok, remaining }
  }
}
```

See `BrassCounterStore` in `src/storage.js` for the full interface including grace guard methods.

## Cryptographic primitives

All functions are pure (no side effects, no I/O). Import individually:

```javascript
import {
  H3,                    // Domain-separated, length-prefixed SHA-256
  deriveEta,             // Verifier-chosen salt η
  deriveNullifierY,      // Deterministic nullifier y
  canonicalOrigin,       // Origin normalization (HTTPS, IDNA, no path)
  windowId,              // Window ID from timestamp
  isInGracePeriod,       // Grace period detection
  deriveTlsBinding,      // TLS channel binding
  bytesToB64url,         // Base64url encoding
  b64urlToBytes,         // Base64url decoding
} from '@veritasacta/verify/crypto';
```

## Protocol specification

See [PROTOCOL.md](./PROTOCOL.md) for the formal specification including:

- Derivation formulas for η, y, IK, and grace nullifiers
- DLEQ proof structure and verification
- Grace-bridge boundary protection
- TLS channel binding
- Security properties and threat model

## Related projects

- [Veritas Acta](https://github.com/VeritasActa) — Decentralized trust infrastructure for humans and AI
- [Acta](https://github.com/VeritasActa/Acta) — Contestable, checkable public record (uses `@veritasacta/verify` for anonymous sybil-resistant identity)
- [ScopeBlind](https://scopeblind.com) — Managed VOPRF issuance service (commercial issuer for the BRASS protocol)

## Security

- All elliptic curve operations use [`@noble/curves`](https://github.com/paulmillr/noble-curves) (audited by Trail of Bits)
- All hash operations use [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (audited)
- Point validation rejects: off-curve, infinity, non-canonical, wrong prefix
- Constant-time byte comparison for proof verification
- Domain-separated, length-prefixed hashing prevents cross-field collisions
- Grace-bridge prevents double-spend at window boundaries

## License

Apache-2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

The BRASS protocol is covered by pending patent applications. Use of this code grants you a royalty-free patent license per Apache License 2.0 Section 3. Clean-room reimplementation of patented constructions without use of this code requires a separate patent license.
