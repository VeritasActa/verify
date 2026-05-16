# Error Code Registry

Every error `@veritasacta/verify` can emit has a stable code,
classification, exit code, and spec reference where applicable.
Consumers should parse the `error` field (from `--json` output)
rather than rely on human-readable text.

## Classification

| Class | Meaning | Exit code |
|---|---|---|
| `tampered` | Signature was tested and failed. Proof of modification. | 1 |
| `undecidable` | Signature could not be tested (malformed, missing key, unsupported algorithm). | 2 |

## Codes

### Tampered (exit 1)

#### `invalid_signature`
- **Description:** Cryptographic signature verification failed over the canonical payload.
- **Spec:** `draft-farley-acta-signed-receipts-03 §6.1`
- **Hint:** The receipt has been modified, or was signed by a different key than the one provided.

#### `chain_break`
- **Description:** `previousReceiptHash` does not match the hash of the preceding receipt.
- **Spec:** `draft-farley-acta-signed-receipts-03 §5.4 Chain Linkage`
- **Hint:** A receipt has been inserted, removed, or reordered in the chain.

#### `commitment_mismatch`
- **Description:** Selective-disclosure commitment does not match the revealed salt+value.
- **Spec:** `AIP-0002 §Disclosure Package Verification`
- **Hint:** The disclosed value does not correspond to the committed hash.

#### `dleq_verification_failed`
- **Description:** VOPRF DLEQ proof verification failed (issuer or client proof invalid).
- **Spec:** `draft-farley-acta-signed-receipts-03 §VOPRF Token Verification`
- **Hint:** The VOPRF token was not produced by a valid issuer, or the proof is malformed.

### Undecidable (exit 2)

#### `embedded_key_rejected`
- **Description:** Receipt contains a verification key in its payload, which is not trusted by default.
- **Spec:** `draft-farley-acta-signed-receipts-03 §Security Considerations — Key Distribution`
- **Hint:** Provide `--key`, `--jwks`, or `--trust-anchor` externally. The deprecated `--allow-embedded-key` restores pre-0.4.0 behaviour for one release cycle.

#### `no_public_key`
- **Description:** Verification key could not be resolved from `--key`, `--jwks`, or a bundle verification block.
- **Hint:** Provide `--key <hex>`, `--jwks <url>`, or `--trust-anchor <file>`.

#### `missing_signature`
- **Description:** Input does not contain a `signature` field.

#### `missing_payload`
- **Description:** Input does not contain a `payload` field.

#### `unsupported_algorithm`
- **Description:** The declared signature algorithm is not supported by this verifier version.
- **Hint:** Hybrid post-quantum algorithms like `ed25519+ml-dsa-65` require v0.6+ for full PQ verification.

#### `non_ascii_key`
- **Description:** An object key contains a non-ASCII character, violating AIP-0001.
- **Spec:** `AIP-0001 §JCS Canonicalization`

#### `malformed_json`
- **Description:** Input could not be parsed as JSON.

#### `malformed_hex`
- **Description:** A hex-encoded value has odd length or contains invalid characters.

#### `unknown_format`
- **Description:** Input does not match any recognized receipt, token, or bundle format.
- **Hint:** Valid formats: v1 receipt, v2 receipt, Passport envelope, audit bundle, KU bundle, VOPRF token.

#### `jwks_fetch_failed`
- **Description:** JWKS endpoint did not return a valid key set.

#### `context_requirement_unmet`
- **Description:** One or more `--require-context` predicates evaluated false at verification time.
- **Spec:** Patent #5 claim 2 — Live-context verification

#### `tier_not_achieved`
- **Description:** Verification succeeded but did not achieve the tier required by `--tier`.

## JSON output format

When `--json` is used, errors appear as:

```json
{
  "valid": false,
  "error": "embedded_key_rejected",
  "errorMeta": {
    "code": "embedded_key_rejected",
    "description": "Receipt contains a verification key in its payload, which is not trusted by default.",
    "class": "undecidable",
    "spec": "draft-farley-acta-signed-receipts-03 §Security Considerations — Key Distribution",
    "hint": "Provide --key, --jwks, or --trust-anchor externally."
  },
  "format": "ed25519-passport",
  "kid": "..."
}
```

Consumers should branch on `error` code, not on `errorMeta.description`
(which is informative but may evolve).
