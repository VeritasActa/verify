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

A verification that makes several checks combines them as §5.3 of the -04 editor's copy (VeritasActa/drafts) has it (from 0.10.26): invalid (exit 1) if any check ran and failed, even when another could not run; undecidable (exit 2) if none failed and at least one could not run; valid (exit 0) only when every check that applies passed. The `error` reported is the first failure, in the order signing input, signature, chain link, connector action, key window, link to the previous receipt; or, when none failed, the first check that could not run. `--json` gives each check's result in `checks`, and the outcome in `outcome`. `--replay-chain` exits 1 if any line is invalid or any link breaks, else 2 if any line could not be checked, else 0.

## Codes

### Tampered (exit 1)

#### `invalid_signature`
- **Description:** Cryptographic signature verification failed over the canonical payload.
- **Spec:** `draft-farley-acta-signed-receipts-03 §6.6 Signature Scope`
- **Hint:** The receipt has been modified, or was signed by a different key than the one provided.

#### `signature_in_signing_input`
- **Description:** The object canonicalized for the signature carries a `signature` member (`null` and the empty string included), which the signing input must never contain.
- **Spec:** `draft-farley-acta-signed-receipts-03 §6.6 Signature Scope`
- **Hint:** Sign `JCS(payload)` over a payload with no signature member. A signature over bytes that contain one is refused even when it verifies.

#### `chain_break`
- **Description:** `previousReceiptHash` does not match the hash of the preceding receipt: the SHA-256 of the JCS of the whole receipt, signature included.
- **Spec:** `draft-farley-acta-signed-receipts-03 §6.7 Chain Hash Scope`
- **Hint:** A receipt has been inserted, removed, reordered or re-signed. A link over the previous receipt's payload alone is refused too, whatever that receipt's `spec` says: no revision of the draft defines one. `--allow-payload-only-links` reads one as a legacy link, counted and warned, for chains written by `verify proxy` and `verify daemon` in 0.9.3 and earlier. `--replay-chain` and `verify chain explore` report this code; there a receipt after the first with no `previousReceiptHash` starts a new chain (§2.2) and is not a `chain_break`. `verify <receipt> --previous <receipt>` reports it for one receipt checked against the receipt the caller says it follows: its link must be that receipt's §6.7 hash, and an absent or `null` link fails too, since a receipt that names no predecessor does not follow the one supplied.

#### `malformed_chain_link`
- **Description:** `previousReceiptHash` is not `sha256:` followed by 64 lowercase hex characters, nor the bare 64-character digest of earlier revisions.
- **Spec:** `draft-farley-acta-signed-receipts-03 §6.7 Chain Hash Scope`
- **Hint:** The signature may be authentic, but the link cannot name any receipt. It is refused whether or not the predecessor is supplied.

#### `commitment_mismatch`
- **Description:** Selective-disclosure commitment does not match the revealed salt+value.
- **Spec:** `AIP-0002 §Disclosure Package Verification`
- **Hint:** The disclosed value does not correspond to the committed hash.

#### `dleq_verification_failed`
- **Description:** VOPRF DLEQ proof verification failed (issuer or client proof invalid).
- **Spec:** `RFC 9497 (VOPRF DLEQ proofs)`
- **Hint:** The VOPRF token was not produced by a valid issuer, or the proof is malformed.

#### `digest_mismatch`
- **Description:** Recomputed SHA-256 of the canonical payload does not match the digest carried in the record (ScopeBlind Gate tuples).
- **Hint:** The payload was modified after the digest was computed, or the digest field was altered.

#### `chain_link_mismatch`
- **Description:** A chained record references a parent digest or leg that does not match the rest of the bundle (ScopeBlind Gate evidence bundles).
- **Hint:** Each record may still be individually authentic; this code means a cross-record link is inconsistent. Check the `[chain]` entries in the error list.

#### `key_mismatch`
- **Description:** The verification key carried in the record does not match the key pinned with `--key`.
- **Hint:** The record was signed by a different identity than the one you required.

#### `schema_invalid`
- **Description:** A cryptographically authentic Gate payload violates the semantic contract of its declared schema.
- **Hint:** Treat the artifact as invalid even if its signature verifies; inspect the semantic error details.

#### `key_outside_validity_window`
- **Description:** The receipt was issued outside the signing key's `valid_from` / `valid_until` window, `[valid_from, valid_until)`.
- **Spec:** `draft-farley-acta-signed-receipts-03 §9.2 Key Compromise`
- **Hint:** The key had been rotated out, or was not yet in use, at the `issued_at` the receipt states. `issued_at` is asserted by the signer, so this catches a key used after an honest rotation, not a compromised key backdated into its window.

### Undecidable (exit 2)

#### `key_window_missing`
- **Description:** `--require-key-window` was given and the key source carries no validity window for the signing key.
- **Spec:** `draft-farley-acta-signed-receipts-03 §9.2 Key Compromise`
- **Hint:** Publish `valid_from` / `valid_until` on the JWK, or verify without the flag; the result then reports the key's validity at issuance as not established.

#### `key_window_unverifiable`
- **Description:** The key source carries a validity window that cannot be applied: a bound that is not an RFC 3339 date-time with its UTC offset written out (`Z` or `±hh:mm`; `null`, a date alone and a time with no offset included), bounds in the wrong order, or a receipt whose `issued_at` is missing or is not such a date-time. The detail names the value and the cause. From 0.10.26 a time with no offset is refused rather than read in the machine's own time zone.
- **Spec:** `draft-farley-acta-signed-receipts-03 §9.2 Key Compromise`

#### `embedded_key_rejected`
- **Description:** Receipt contains a verification key in its payload, which is not trusted by default.
- **Spec:** `draft-farley-acta-signed-receipts-03 §9.5 Key Distribution and Trust Anchors`
- **Hint:** Provide `--key` or `--jwks` externally. The deprecated `--allow-embedded-key` restores pre-0.4.0 behaviour for one release cycle.

#### `no_public_key`
- **Description:** Verification key could not be resolved from `--key`, `--jwks`, or a bundle verification block.
- **Hint:** Provide `--key <hex>`, or `--jwks <url|file>`. `--trust-anchor` was never implemented and is refused (exit 2) since 0.10.25.

#### `missing_signature`
- **Description:** Input does not contain a `signature` field.

#### `missing_payload`
- **Description:** Input does not contain a `payload` field.

#### `unsupported_algorithm`
- **Description:** The declared signature algorithm is not supported by this verifier version.
- **Hint:** Hybrid post-quantum algorithms like `ed25519+ml-dsa-65` require v0.6+ for full PQ verification.

#### `unsupported_chain_hash_algorithm`
- **Description:** `previousReceiptHash` names a hash algorithm other than sha256, which this verifier does not implement.
- **Spec:** `draft-farley-acta-signed-receipts-03 §6.7 Chain Hash Scope`
- **Hint:** Draft §6.7 requires refusing a link whose prefix names an unimplemented algorithm rather than assuming SHA-256 from its length.

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
- **Description:** JWKS endpoint did not return a valid key set, or the key set has no key for the receipt's `kid`. With `--replay-chain`, a key set that cannot be read stops the replay (exit 2); a line whose `kid` it does not have is undecidable.

#### `context_requirement_unmet`
- **Description:** One or more `--require-context` predicates evaluated false at verification time.
- **Spec:** Patent #5 claim 2: Live-context verification

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
    "spec": "draft-farley-acta-signed-receipts-03 §9.5 Key Distribution and Trust Anchors",
    "hint": "Provide --key or --jwks externally."
  },
  "format": "ed25519-passport",
  "kid": "..."
}
```

Consumers should branch on `error` code, not on `errorMeta.description`
(which is informative but may evolve).

- `legacy_non_jcs_signature`: a signature matches the historical numeric-key encoding, not RFC 8785. Regenerate using JCS, or explicitly inspect with `--allow-legacy-canonicalization`; strict verification does not accept it.
