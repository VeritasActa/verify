# Cosign / Sigstore compatibility design (v0.6.0 target)

Not a build artifact yet. Design spec for the compatibility layer that
lands in v0.6.0 of `@veritasacta/verify`.

## Goal

Make Veritas Acta receipts verifiable by `cosign verify-blob`, and
vice-versa: `cosign`-signed blobs verifiable with `@veritasacta/verify`.

## Compatibility surfaces

### 1. DSSE envelope wrapping

Wrap a Veritas Acta receipt in a DSSE (Dead Simple Signing Envelope)
payload of type `application/vnd.acta.receipt+json`:

```json
{
  "payloadType": "application/vnd.acta.receipt+json",
  "payload": "<base64(receipt JSON)>",
  "signatures": [
    {
      "keyid": "sha256:<jwk-thumbprint>",
      "sig": "<base64(Ed25519 sig)>"
    }
  ]
}
```

This makes the receipt parseable by any DSSE-aware tool.

### 2. Rekor anchor

Anchor the DSSE envelope hash in Rekor:

```bash
cosign attest-blob --type veritas-acta --predicate receipt.json blob.bin
```

Produces a Rekor inclusion proof that can be verified later without
accessing the original log.

### 3. in-toto predicate type

Register `https://veritasacta.com/attestation/decision-receipt/v1` as
an in-toto predicate type (PR #549 in in-toto/attestation). Once
merged, any cosign-backed flow can emit Veritas Acta receipts as
in-toto attestations.

### 4. Policy bundle for cosign verify-blob

```bash
cosign verify-blob --signature sig.json --certificate cert.pem \
  --certificate-identity-regexp '^@veritasacta/verify@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  blob.bin
```

Composes with Sigstore's keyless signing pattern.

## Implementation path for v0.6.0

1. Add `src/engines/dsse.js` — DSSE envelope wrap/unwrap
2. Add `--emit-dsse` flag — wraps verification output as a DSSE envelope
3. Add `--verify-dsse` flag — accepts a DSSE-wrapped receipt as input
4. Add `--rekor-anchor <url>` — verifies Rekor inclusion proof when
   present
5. Publish the in-toto predicate type once PR #549 lands
6. Add `cosign-verify-blob` examples to README

## Non-goals

- Not replacing cosign or Sigstore. The goal is composition, not
  substitution.
- Not running our own transparency log. Rekor is already operating at
  scale.

## v0.7.0 extension

- Fulcio-style keyless signing for issuers (OIDC → short-lived signing
  cert) as a complement to long-lived operator keys.
- Rekor v2 integration when it ships.

## Open questions

1. Should we require DSSE wrapping to be explicit, or auto-detect on
   input?
2. How does the DSSE `keyid` field compose with Veritas Acta's `kid`
   field?
3. Should the Sigil commitment extend to include DSSE wrap/unwrap code
   when that ships?
