# @veritasacta/verify

**Check signed records yourself, without contacting the issuing service.**

An offline CLI and a shared browser receipt engine. Supply a receipt and a public
key obtained through a separate trusted channel, then apply your own trust policy.
No account, proxy, signing daemon or onboarding step is required to verify a receipt.

[Try the browser sample](https://www.veritasacta.com/verify?sample=current) ·
[Receipt specification](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) ·
[Conformance evidence](https://www.veritasacta.com/conformance)

## Verify an existing receipt

```bash
npm install -g @veritasacta/verify
verify receipt.json --key YOUR_INDEPENDENTLY_OBTAINED_PUBLIC_KEY
```

The key is 64 hexadecimal characters. Do not treat a key supplied with an unknown
receipt as an independent trust pin. This verification path runs offline once the
package is installed; installation and explicitly requested URL/JWKS lookups use
the network.

To try the public example, download [this receipt](samples/current-receipt.json)
and use its **demonstration-only** key:

```bash
verify current-receipt.json --key ebb8cf3efc78717c50e7c438c0ad5498f8fa4e09607fea1e030ac129b5965225
```

A valid signature is not proof of claim truth, complete action coverage, signer
authority or recipient acceptance. A signed timestamp is an issuer assertion,
not an independent timestamp.

## Read the outcome correctly

| Outcome | Meaning | Next step |
| --- | --- | --- |
| Verified / exit 0 | The checks implemented for this profile passed | Apply identity, authority and reliance policies; read warnings and binding scope |
| Failed / exit 1 | A verification check failed | Check the expected key, signature, structure and reported error |
| Not checked / exit 2 | The verifier could not decide | Supply missing material or use a supported format/algorithm |

**Exit 1 does not prove tampering.** Supplying the wrong expected key can produce
the same result. Some legacy JSON error categories use the name `tampered` for
compatibility; it denotes failed verification, not a forensic conclusion.
See [error codes](ERRORS.md) and the profile-specific output.

## Browser and CLI

Both use `src/detect.js`, `src/engines/ed25519-receipt.js` and the same canonicalizer.
The browser bundle is published in `browser/`, with a SHA-256 build manifest.

The browser accepts individual Ed25519 envelopes, v2 structured receipts, v1 flat
receipts and historical website `receipt_version: "1.0"` receipts. That historical
profile excluded `public_key` from signing and is explicitly labelled; it is not
silently promoted to draft-03 conformance. All browser profiles require an external
key. Unsupported formats are **not checked**, not reported as bad signatures.

Both entry points reject duplicate JSON members before parsing. The browser limits
input to 1 MiB and depth 64; the CLI file parser allows 50 MiB and depth 128.
Bundles and specialist profiles, including selective disclosure, VOPRF, Knowledge
Units, Gate evidence and governed-run manifests, require the CLI. Profile success
only establishes the checks named in that output, not universal completeness.

## Choose a guide

| Task | Guide |
| --- | --- |
| Verify bundles, chains, prompts or specialist artifacts | [Advanced reference](docs/reference.md) |
| Issue receipts or configure a proxy/daemon | [Issuance and adapters](docs/issuance.md) |
| Understand threats and limitations | [Threat model](THREAT-MODEL.md) |
| Report a vulnerability | [Security policy](SECURITY.md) |
| Inspect exact release changes | [Changelog](CHANGELOG.md) |

## Release integrity, not publisher authentication

`verify --self-check` recomputes monitored source hashes against a **bundled integrity
commitment** (the Sigil). It detects drift from that commitment. Someone replacing
both the code and commitment can create a new internally consistent package.

It does **not** independently authenticate the publisher or establish a canonical
release. Pin a reference obtained independently and inspect release provenance.
`--attest` is a local, self-signed integrity statement; separately pin its key before
relying on it.

## Release and standards status

<!-- release-manifest:start -->
Verifier: **[0.10.25](https://github.com/VeritasActa/verify/releases/tag/v0.10.25)**. Status reviewed 2026-10-19.

- [draft-farley-acta-signed-receipts-03](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/): active individual Internet-Draft.
- [draft-farley-acta-knowledge-units-00](https://datatracker.ietf.org/doc/draft-farley-acta-knowledge-units/): expired individual Internet-Draft (expired 2026-10-08).

Internet-Drafts are proposals, not adopted IETF standards or endorsements.
<!-- release-manifest:end -->

[`release-manifest.json`](release-manifest.json) is the source for version/status
blocks in this README, the website, the organisation profile and draft index.
`node scripts/sync-public-metadata.mjs --check` checks sibling repository copies.
No draft is revised or resubmitted by this synchronization.

## Development and maintainership

Maintained by Tom Farley / ScopeBlind. Independent verification does not imply
independent organizational governance. Contributions should include reproducible
fixtures and negative cases. [Open an issue](https://github.com/VeritasActa/verify/issues)
for interoperability questions.

```bash
npm ci
npm run build:browser
npm test
npm run check:browser
npm run check:sigil
npm run test:conformance
```

Apache-2.0. See [LICENSE](LICENSE) and [PATENTS.md](PATENTS.md) for the actual terms.
The Acta public record is a [separate reference application](https://github.com/VeritasActa/Acta).
ScopeBlind / Legate are commercial applications, not prerequisites for verification.
