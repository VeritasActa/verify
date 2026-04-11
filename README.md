# @veritasacta/verify

Verify signed receipts offline. No accounts, no API calls, no trust required.

**Apache-2.0 · Ed25519 · Offline · Zero dependencies beyond `@noble/curves`**

```bash
npm install @veritasacta/verify
```

Part of the [Veritas Acta](https://github.com/VeritasActa) project — open evidence protocol for machine decisions.

## Self-Test

```bash
npx @veritasacta/verify --self-test
```

```
✓ Sample receipt: VALID (Ed25519, kid: gateway-001)
✓ Sample bundle: VALID (3/3 receipts verified)
✓ Tampered receipt: REJECTED (signature mismatch)
No ScopeBlind servers were contacted.
```

Exit codes:
- `0` — all signatures valid
- `1` — tampered or invalid signature
- `2` — malformed input

## What It Does

Every time an AI agent makes a decision through [protect-mcp](https://www.npmjs.com/package/protect-mcp), that decision is signed with Ed25519. The signature covers:

- **Tool name** — what was called
- **Decision** — allow, deny, rate_limited
- **Policy digest** — which policy version governed the decision
- **Timestamp** — when it happened
- **Payload digest** — SHA-256 of the full input/output

`@veritasacta/verify` checks these signatures. It works offline, requires no accounts, and never contacts any server.

## Usage

### Verify a single receipt

```bash
npx @veritasacta/verify receipt.json
```

### Verify with an explicit public key

```bash
npx @veritasacta/verify receipt.json --key <hex-encoded-ed25519-pubkey>
```

### Verify an audit bundle

```bash
npx @veritasacta/verify bundle.json
```

Bundles are self-contained: they include receipts + the public key used to sign them.

### Programmatic API

```javascript
import { verifyReceipt, verifyBundle } from '@veritasacta/verify';

const result = await verifyReceipt(receiptJson, publicKeyHex);
// { valid: true, algorithm: 'Ed25519', kid: 'gateway-001' }

const bundleResult = await verifyBundle(bundleJson);
// { valid: true, receipts: 47, verified: 47, failed: 0 }
```

## Receipt Format

Receipts follow the [IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) `draft-farley-acta-signed-receipts-01`:

```json
{
  "type": "decision",
  "version": 2,
  "algorithm": "Ed25519",
  "kid": "gateway-001",
  "timestamp": "2026-04-10T12:00:00Z",
  "payload": {
    "tool": "read_file",
    "decision": "allow",
    "policy_digest": "sha256:a1b2c3..."
  },
  "signature": "base64url-encoded-ed25519-signature"
}
```

The signature is computed over the [JCS-canonicalized](https://www.rfc-editor.org/rfc/rfc8785) payload, ensuring deterministic verification regardless of JSON key ordering.

## How Verification Works

```
Receipt JSON
    ↓
Extract payload + signature
    ↓
JCS-canonicalize the payload
    ↓
Ed25519.verify(signature, canonical_payload, public_key)
    ↓
exit 0 (valid) or exit 1 (tampered)
```

No network calls. No trust assumptions. The only input is the receipt and the public key.

## Issuer-Blind Design

The verifier never learns *who* generated the receipt — only that it was signed by a key matching the provided public key. This is a deliberate design property:

- **Compliance teams** can verify agent behavior without accessing the agent runtime
- **Third-party auditors** can check receipts without org access
- **Cross-organization verification** works without federation or shared infrastructure

## Security

- Ed25519 signatures via [`@noble/curves`](https://github.com/paulmillr/noble-curves) (audited by Trail of Bits)
- SHA-256 hashing via [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) (audited)
- JCS canonicalization for deterministic payload serialization
- No eval, no dynamic imports, no network access during verification

## Related Projects

| Project | Description |
|---------|-------------|
| [VeritasActa/Acta](https://github.com/VeritasActa/Acta) | Open evidence protocol — charter, spec, types |
| [protect-mcp](https://www.npmjs.com/package/protect-mcp) | Security gateway that produces signed receipts |
| [ScopeBlind/verify-mcp](https://github.com/ScopeBlind/verify-mcp) | MCP server exposing verification as agent tools |
| [VeritasActa/drafts](https://github.com/VeritasActa/drafts) | IETF Internet-Draft source files |
| [@veritasacta/protocol](https://www.npmjs.com/package/@veritasacta/protocol) | Full evidence protocol types (TypeScript) |

## Protocol Specification

The receipt format is standardized as an IETF Internet-Draft:

**[draft-farley-acta-signed-receipts-01](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)** — Signed Decision Receipts for Machine-to-Machine Access Control

## License

Apache-2.0 — see [LICENSE](./LICENSE).

Free to use, modify, and redistribute. The Apache-2.0 license includes a royalty-free patent grant (Section 3) for all constructions implemented in this code.

---

> **Looking for the VOPRF/BRASS rate-limiting library?** The anonymous credential primitives have moved to a [separate repository](https://github.com/VeritasActa). This package (`@veritasacta/verify`) is now the offline receipt verification CLI.
