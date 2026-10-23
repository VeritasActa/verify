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

A verification that makes several checks combines them as §5.3 of the -04 editor's copy (VeritasActa/drafts) has it (from 0.10.26): invalid (exit 1) if any check ran and failed, even when another could not run; undecidable (exit 2) if none failed and at least one could not run; valid (exit 0) only when every check that applies passed. The `error` reported is the first failure, in the order signing input, signature, carried key and issuer (both from 0.10.27), chain link, connector action, key window, link to the previous receipt; or, when none failed, the first check that could not run. `--json` gives each check's result in `checks`, and the outcome in `outcome`. `--replay-chain` exits 1 if any line is invalid or any link breaks, else 2 if any line could not be checked, else 0, and from 0.10.27 an audit bundle does the same over its receipts.

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
- **Spec:** `AIP-0002 §Disclosure Package Verification`; for `--disclosure-file`, `draft-farley-acta-signed-receipts-03 §6.5 Selective Disclosure`
- **Hint:** The disclosed value does not correspond to the committed hash. With `--disclosure-file`, each disclosure's Merkle proof must reconstruct the `committed_fields_root` in the receipt's signed bytes (an envelope's payload, a flat receipt's top level). From 0.10.27 a proof's leaf count is read as `tree_size`, as §6.5 names it, and `treeSize` is still accepted. With `--disclose`, the commitment is read from the `_commitments` map in the signed bytes, the same way.

#### `dleq_verification_failed`
- **Description:** VOPRF DLEQ proof verification failed (issuer or client proof invalid).
- **Spec:** `RFC 9497 (VOPRF DLEQ proofs)`
- **Hint:** The VOPRF token was not produced by a valid issuer, or the proof is malformed.

#### `invalid_piI`
- **Description:** A VOPRF token's issuer DLEQ proof does not verify against the issuer key given with `--key`.
- **Spec:** `RFC 9497 (VOPRF DLEQ proofs)`
- **Hint:** The token was not issued under that key, or the proof was altered. Exit 1 from 0.11.0; 0.10.28 exited 2 for it and checked the proof against the key the token carries.

#### `invalid_piC`
- **Description:** A VOPRF token's client DLEQ proof does not verify over its own transcript.
- **Spec:** `RFC 9497 (VOPRF DLEQ proofs)`
- **Hint:** A member the client proof binds (the scope, the request digest, the nonce) was altered after redemption. Exit 1 from 0.11.0; 0.10.28 exited 2 for it.

#### `issuer_key_mismatch`
- **Description:** A VOPRF token carries an `issuer_public_key` that is not the issuer key given with `--key`.
- **Spec:** `draft-farley-acta-signed-receipts-03 §9.5 Key Distribution and Trust Anchors`
- **Hint:** The token names a different issuer from the one you required. A key the token carries is never used to verify it. A BRASS 2.0 redemption reported this code before, with exit 2.

#### `digest_mismatch`
- **Description:** Recomputed SHA-256 of the canonical payload does not match the digest carried in the record (ScopeBlind Gate tuples).
- **Hint:** The payload was modified after the digest was computed, or the digest field was altered.

#### `chain_link_mismatch`
- **Description:** A chained record references a parent digest or leg that does not match the rest of the bundle (ScopeBlind Gate evidence bundles).
- **Hint:** Each record may still be individually authentic; this code means a cross-record link is inconsistent. Check the `[chain]` entries in the error list.

#### `key_mismatch`
- **Description:** The verification key carried in the record does not match the key pinned with `--key`. For an Acta receipt (from 0.10.27): a `public_key`, `verification_key` or `verification_jwk` member of the signed bytes (an envelope's payload; a flat receipt, and a v2 receipt's payload) is not the key the receipt is verified with, from `--key`, `--jwks` or a bundle trusted with `--trust-bundle-keys`. Keys are compared as 32 bytes (hex in either case, base64 or base64url, or an OKP Ed25519 JWK); a value in none of those forms is not that key.
- **Spec:** `draft-farley-acta-signed-receipts-03 §9.5 Key Distribution and Trust Anchors`; §5.3 Verification Outcomes of the -04 editor's copy (VeritasActa/drafts)
- **Hint:** The record names a different identity than the one you required. A key the receipt carries is never used to verify it, and one that is not the trust-anchored key makes it invalid even when the signature verifies. The JSON result reports the check as `checks.carried_key`.

#### `issuer_kid_mismatch`
- **Description:** An envelope's payload names an `issuer_id` that is not its signature object's `kid`, or names one while the signature object has no `kid`. New in 0.10.27; 0.10.26 never compared the two.
- **Spec:** `draft-farley-acta-signed-receipts-03 §2.2 Payload` (`issuer_id` "MUST match the kid field in the signature object"); §5.3 Verification Outcomes of the -04 editor's copy (VeritasActa/drafts)
- **Hint:** The signed payload names a different issuer from the key identifier beside it. The check reads the bytes alone, so it counts with or without a key, beside a signature that could not be checked. A payload with no `issuer_id` is not checked: `payloadNotes` names the gap, and the outcome does not change. The flat shapes are not checked. The JSON result reports the check as `checks.issuer_kid`.

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
- **Description:** The key source carries a validity window that cannot be applied: a bound that is not an RFC 3339 date-time with its UTC offset written out (`Z` or `±hh:mm`; `null`, a date alone and a time with no offset included), bounds in the wrong order, or a receipt whose signed `issued_at` is missing or is not such a date-time string. The detail names the value and the cause. From 0.10.26 a time with no offset is refused rather than read in the machine's own time zone. From 0.10.27 only the `issued_at` the signature covers is read: an envelope's `payload.issued_at`, a flat receipt's top-level `issued_at`. An `issued_at` or `timestamp` beside an envelope's payload, a `timestamp` anywhere, and a number are not read in its place.
- **Spec:** `draft-farley-acta-signed-receipts-03 §9.2 Key Compromise`

#### `embedded_key_rejected`
- **Description:** Receipt contains a verification key in its payload, which is not trusted by default.
- **Spec:** `draft-farley-acta-signed-receipts-03 §9.5 Key Distribution and Trust Anchors`
- **Hint:** Provide `--key` or `--jwks` externally. The deprecated `--allow-embedded-key` restores pre-0.4.0 behaviour for one release cycle. With a key from `--key` or `--jwks`, a key the receipt carries must be that key: from 0.10.27 one that is not is `key_mismatch` (exit 1). From 0.11.0 it is also the code for any other file checked only against a key it carries (a Gate tuple or bundle, a macro snapshot or track record, a governed receipt, a proof or context pack, repository evidence, a standard file or a run manifest, with no `--key`): undecidable by default. `--allow-carried-key` accepts such a result, marked `carriedKeyOnly` with a notice that the signature proves nothing about who signed; `--strict` refuses it even then.

#### `no_public_key`
- **Description:** No verification key from a trust anchor outside the receipt: none was given with `--key` or `--jwks`. From 0.10.27 an audit bundle's own `verification.signing_keys` are not one, since they arrive in the file being verified.
- **Hint:** Provide `--key <hex>`, or `--jwks <url|file>`. For an audit bundle, `--trust-bundle-keys` checks the receipts with the keys the bundle carries, reported as `keySource: bundle`; a valid result then shows only that the receipts match keys in the same file. `--trust-anchor` was never implemented and is refused (exit 2) since 0.10.25.

#### `missing_signature`
- **Description:** Input does not contain a `signature` field.

#### `missing_issuer_public_key`
- **Description:** No issuer key was given with `--key` for a VOPRF token. The `issuer_public_key` a token carries is not one, since anyone can issue a token under a key of their own.
- **Spec:** `draft-farley-acta-signed-receipts-03 §9.5 Key Distribution and Trust Anchors`
- **Hint:** Give the issuer's public key (base64url compressed P-256 point) with `--key`. Before 0.11.0 a token checked with no key was verified against the key it carries.

#### `issuer_key_pin_required`
- **Description:** No issuer key was given with `--key` for a BRASS 2.0 redemption.
- **Hint:** Give the issuer's public key (base64url compressed P-256 point) with `--key`.

#### `missing_payload`
- **Description:** Input does not contain a `payload` field.

#### `signature_not_checked`
- **Description:** `verify prompt`: the receipt or Sigstore bundle names the prompt's hash, but its own signature is not checked, so nothing establishes who made the assertion. 0.10.28 reported this as verified provenance (exit 0).
- **Hint:** Verify the receipt with `verify <receipt.json> --key <hex>`, or the bundle with a Sigstore verifier. `--expected-hash` checks the prompt against a hash you supply.

#### `no_receipts`
- **Description:** A Knowledge Unit carries no receipts, so nothing in it was verified.
- **Spec:** `draft-farley-acta-knowledge-units-00 §8`
- **Hint:** A KU is checked through the receipts it carries: invalid if one fails, else undecidable if there is none or one cannot be checked (a receipt in a format this verifier does not read is reported as `unknown_format`). Its `receipt_sig` and `receipt_hash` are not checked either (`receipt_binding_not_checked`), so a KU is never valid. 0.10.28 reported a KU with no receipts, or only unreadable ones, as valid.

#### `receipt_binding_not_checked`
- **Description:** A Knowledge Unit's `receipt_sig` and `receipt_hash` are present and not checked, so nothing binds its question, answers or consensus to its receipts. New in 0.11.0, which reports such a KU undecidable; 0.10.28 reported it valid when its receipts verified.
- **Spec:** `draft-farley-acta-knowledge-units-00 §8 Receipt Binding`; §11 Security Considerations (Receipt Replay): verifiers MUST recompute the chain
- **Hint:** §8 does not say which receipts form each round (a KU has no member for them, and round 2 records carry no slot), whether `receipt_hash` is bare hex (§3.6) or `sha256:`-prefixed (the §10 example), or whether `receipt_sig` signs the digest's bytes or its text, so this verifier does not recompute it. The embedded receipts are still checked, and one that fails makes the KU invalid (exit 1).

#### `unsupported_algorithm`
- **Description:** The declared signature algorithm is not supported by this verifier version.
- **Hint:** ML-DSA-65 is not implemented, alone (`ML-DSA-65`) or in a hybrid such as `ed25519+ml-dsa-65`, so a receipt that declares it is undecidable (`unsupported_algorithm`, exit 2). Verify it with a verifier that implements the algorithm.

#### `unsupported_chain_hash_algorithm`
- **Description:** `previousReceiptHash` names a hash algorithm other than sha256, which this verifier does not implement.
- **Spec:** `draft-farley-acta-signed-receipts-03 §6.7 Chain Hash Scope`
- **Hint:** Draft §6.7 requires refusing a link whose prefix names an unimplemented algorithm rather than assuming SHA-256 from its length.

#### `malformed_encoding`
- **Description:** The receipt could not be encoded or decoded for the signature check: the signature or the key is not valid hexadecimal, or the signed object cannot be canonicalized (a member name that is not ASCII, as AIP-0001 requires, or a value JCS cannot encode). The detail names the cause.
- **Spec:** RFC 8785 (JCS); `AIP-0001 §JCS Canonicalization`
- **Hint:** Supply the key as 64 hexadecimal characters, and check that the receipt's signature is hexadecimal and its member names are ASCII. Nothing about the signature was established. The browser bundle reports input it cannot interpret safely with the same code. Registered in 0.10.27; earlier releases emitted it without an entry, so an audit bundle that failed with it was shown as `INVALID` rather than `NOT CHECKED`.

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

#### `disclosure_not_applied`
- **Description:** A disclosure was given and could not be applied: a `--disclosure-file` that cannot be read or parsed, holds no disclosure, or meets a receipt whose signed bytes carry no `committed_fields_root`; or a `--disclose` value that is not `field:salt:value`, or one given for a receipt whose signed bytes carry no `_commitments` map. New in 0.10.27; 0.10.26 ignored such a disclosure, or reported the unregistered code `disclosure_file_load_failed: <message>` for a file it could not read.
- **Spec:** `draft-farley-acta-signed-receipts-03 §6.5 Selective Disclosure`; `AIP-0002 §Disclosure Package Verification`
- **Hint:** The root and the map are read from the signed bytes: an envelope's payload, or the top level of a flat receipt. One beside an envelope's payload is not signed and is not used. Nothing in the disclosure was verified. A failure found by another check stays the outcome.

#### `jwks_fetch_failed`
- **Description:** JWKS endpoint did not return a valid key set, or the key set has no key for the receipt's `kid`. With `--replay-chain`, a key set that cannot be read stops the replay (exit 2); a line whose `kid` it does not have is undecidable. From 0.10.27 an audit bundle takes each receipt's key from the set by that receipt's `kid` the same way: a receipt whose `kid` the set lacks is undecidable, and a set that cannot be read checks nothing (exit 2).

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
