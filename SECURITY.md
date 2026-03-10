# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `@veritasacta/verify`, please report it responsibly.

**Email:** [security@veritasacta.com](mailto:security@veritasacta.com)

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide an initial assessment within 7 days.

## Scope

This policy covers:
- The `@veritasacta/verify` npm package
- All code in the [VeritasActa/verify](https://github.com/VeritasActa/verify) repository

## Cryptographic Dependencies

This library delegates all elliptic curve and hashing operations to:
- **[@noble/curves](https://github.com/paulmillr/noble-curves)** — audited by Cure53 (Feb 2024)
- **[@noble/hashes](https://github.com/paulmillr/noble-hashes)** — audited by Cure53 (Feb 2024)

We do not implement custom cryptographic primitives. If you find a vulnerability in the noble libraries, please report it to their maintainer directly.

## Security Properties

The BRASS protocol provides the following security guarantees:

| Property | Guarantee |
|----------|-----------|
| **Issuer blindness** | The issuer cannot determine which scope a token will be redeemed against |
| **Nullifier determinism** | Same token + same scope always produces the same nullifier |
| **Unlinkability** | Different scopes produce unrelated nullifiers from the same token |
| **Proof soundness** | DLEQ proofs are computationally binding under the discrete log assumption on P-256 |
| **Offline verification** | The issuer is never contacted during token redemption |

## Known Limitations

- **MemoryStore** is not suitable for distributed deployments (no cross-process synchronization)
- **KVStore** (Cloudflare KV) is eventually consistent — overspend is bounded but possible during replication lag
- This library implements the **verifier side** only. It does not issue tokens.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
