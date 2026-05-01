# Test vectors

Reference fixtures for Knowledge Unit interoperability.

Shipped to support the cross-verify work tracked in
[issue #2](https://github.com/VeritasActa/verify/issues/2) with
[agent-passport-system](https://www.npmjs.com/package/agent-passport-system).

## Files

| File | Purpose |
|------|---------|
| [`jcs-test-vectors.json`](jcs-test-vectors.json) | JCS canonicalization conformance. 9 cases. Feed each `input` to your canonicalizer and compare the output string and SHA-256 to the expected values. Includes the AIP-0001 ASCII-only key restriction case. |
| [`cross-verify-bundle.json`](cross-verify-bundle.json) | MUST accept. One complete Knowledge Unit: 4 models × 2 rounds + 1 synthesis + 1 aggregate = 10 Ed25519-signed receipts, hash-chained via `payload.previousReceiptHash`. Includes an APS `DecisionLineageReceipt` whose verification key is independently anchored via [`keys/aps-ku-cross-verify.jwks`](keys/aps-ku-cross-verify.jwks). |
| [`cross-verify-embedded-key-bundle.json`](cross-verify-embedded-key-bundle.json) | MUST reject. Deliberately preserves the embedded-key anti-pattern so verifiers can prove they reject verification keys transported inside a receipt or bundle without an independent anchor. |
| [`keys/aps-ku-cross-verify.jwks`](keys/aps-ku-cross-verify.jwks) | Sidecar JWKS for the APS cross-verification fixture. Referenced by `external_receipts.aps.verification_key_ref`. |
| [`selective-disclosure-salted-commit.json`](selective-disclosure-salted-commit.json) | AIP-0002 salted SHA-256 commitment reference. The Grok-4.20 round-1 dissenting response is published with `response.position` and `response.confidence` replaced by commitments. The unsigned `witness` block carries salts + plaintext to unlock them. |
| [`generate.mjs`](generate.mjs) | The generator. Deterministic: same seed produces byte-identical output. Run `node generate.mjs <outdir>` from a workspace with `@veritasacta/artifacts` installed. |

## Verification

```bash
# Individual receipt
npx @veritasacta/verify test-vectors/cross-verify-bundle.json --bundle
# → Bundle: VALID
#   Total: 10  Passed: 10  Failed: 0

# Positive APS cross-layer fixture with sidecar-anchored key
npx @veritasacta/verify test-vectors/cross-verify-bundle.json \
  --bundle --jwks test-vectors/keys/aps-ku-cross-verify.jwks

# Negative embedded-key fixture
npx @veritasacta/verify test-vectors/cross-verify-embedded-key-bundle.json --bundle
# → MUST fail non-zero:
#   verification key transported inside receipt without independent anchor

# Selective-disclosure receipt (redacted shape, signature over redacted payload)
npx @veritasacta/verify test-vectors/selective-disclosure-salted-commit.json
# Note: CLI input shape here is the `redacted_receipt` field; pass it directly
# to the CLI if your tooling needs a single-artifact input.
```

## Interop expectations

For a third-party canonicalizer + verifier to pass:

1. For each entry in `jcs-test-vectors.json`, output bytes equal `canonical` and SHA-256 equals `sha256`.
2. For the ASCII-only case, the canonicalizer MUST throw when a key contains non-ASCII.
3. For `cross-verify-bundle.json`, every receipt individually verifies under the
   `verification.signing_keys[].kid` that matches its `kid` field.
4. For `cross-verify-bundle.json`, the APS receipt verifier MUST resolve
   `external_receipts.aps.verification_key_ref` to the sidecar JWKS and MUST NOT
   rely on a verification key transported inside the receipt or bundle.
5. For `cross-verify-embedded-key-bundle.json`, a verifier MUST reject with
   `verification key transported inside receipt without independent anchor`.
6. For `selective-disclosure-salted-commit.json`, the redacted receipt verifies
   without the witness, and for each entry in `witness.disclosures`:
   `sha256(salt + ":" + JSON.stringify(plaintext))` equals `expected_commitment`.

## Determinism

All signing keys derive from a fixed seed via SHA-256. Salts and timestamps are
constants. Re-running `generate.mjs` produces byte-identical files. If a later
`@veritasacta/artifacts` version changes canonicalization in a non-compatible
way, these fixtures will reveal it immediately.
