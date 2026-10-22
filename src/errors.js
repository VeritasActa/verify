/**
 * Canonical error codes emitted by the verifier.
 *
 * Each code has a stable name, human-readable description, spec reference
 * where applicable, and classification (tampered / undecidable) that
 * drives the process exit code.
 *
 * References:
 *   - draft-farley-acta-signed-receipts-03 (each spec below names the section a code enforces; the draft
 *     defines no error registry of its own)
 *
 * @module verify-cli/src/errors
 * @license Apache-2.0
 */

/**
 * @typedef {'tampered' | 'undecidable' | 'unknown'} ErrorClass
 */

/**
 * @typedef {Object} ErrorMeta
 * @property {string} code
 * @property {string} description
 * @property {ErrorClass} class
 * @property {string} [spec]       spec section reference
 * @property {string} [hint]       user-facing remediation hint
 */

/** @type {Record<string, ErrorMeta>} */
export const ERROR_REGISTRY = {
  // --- Tampered (exit 1) ---
  invalid_signature: {
    code: 'invalid_signature',
    description: 'Cryptographic signature verification failed over the canonical payload.',
    class: 'tampered',
    spec: 'draft-farley-acta-signed-receipts-03 §6.6 Signature Scope',
    hint: 'The receipt has been modified or signed by a different key than the one provided.',
  },
  signature_in_signing_input: {
    code: 'signature_in_signing_input',
    description: 'The object canonicalized for the signature carries a signature member (null and the empty string included), which the signing input must never contain.',
    class: 'tampered',
    spec: 'draft-farley-acta-signed-receipts-03 §6.6 Signature Scope',
    hint: 'Sign JCS(payload) over a payload with no signature member. A signature over bytes that contain one is refused even when it verifies.',
  },
  chain_break: {
    code: 'chain_break',
    description: 'previousReceiptHash does not match the hash of the preceding receipt.',
    class: 'tampered',
    spec: 'draft-farley-acta-signed-receipts-03 §6.7 Chain Hash Scope',
    hint: 'A receipt has been inserted, removed, reordered or re-signed. With --previous, the receipt does not name the one supplied, or names none. A link over the previous receipt\'s payload alone is refused too; --allow-payload-only-links reads one as a legacy link.',
  },
  malformed_chain_link: {
    code: 'malformed_chain_link',
    description: 'previousReceiptHash is not "sha256:" followed by 64 lowercase hex characters, nor the bare 64-character digest of earlier revisions.',
    class: 'tampered',
    spec: 'draft-farley-acta-signed-receipts-03 §6.7 Chain Hash Scope',
    hint: 'The signature may be authentic, but the link cannot name any receipt. It is refused whether or not the predecessor is supplied.',
  },
  commitment_mismatch: {
    code: 'commitment_mismatch',
    description: 'Selective-disclosure commitment does not match the revealed salt+value.',
    class: 'tampered',
    spec: 'AIP-0002 §Disclosure Package Verification',
    hint: 'The disclosed value does not correspond to the committed hash.',
  },
  dleq_verification_failed: {
    code: 'dleq_verification_failed',
    description: 'VOPRF DLEQ proof verification failed (issuer or client proof invalid).',
    class: 'tampered',
    spec: 'RFC 9497 (VOPRF DLEQ proofs)',
    hint: 'The VOPRF token was not produced by a valid issuer, or the proof is malformed.',
  },
  digest_mismatch: {
    code: 'digest_mismatch',
    description: 'Recomputed SHA-256 of the canonical payload does not match the digest carried in the record.',
    class: 'tampered',
    hint: 'The payload was modified after the digest was computed, or the digest field was altered.',
  },
  chain_link_mismatch: {
    code: 'chain_link_mismatch',
    description: 'A chained record references a parent digest or leg that does not match the rest of the bundle.',
    class: 'tampered',
    hint: 'Each record may still be individually authentic; this code means a cross-record link is inconsistent. Check the [chain] entries in the error list.',
  },
  key_mismatch: {
    code: 'key_mismatch',
    description: 'The verification key carried in the record does not match the key pinned with --key. For an Acta receipt (from 0.10.27): a public_key, verification_key or verification_jwk member of the signed bytes is not the key from --key, --jwks or a bundle trusted with --trust-bundle-keys.',
    class: 'tampered',
    spec: 'draft-farley-acta-signed-receipts-03 §9.5 Key Distribution and Trust Anchors; §5.3 Verification Outcomes of the -04 editor\'s copy (VeritasActa/drafts)',
    hint: 'The record names a different identity than the one you required. A key the receipt carries is never used to verify it, and one that is not the trust-anchored key makes it invalid even when the signature verifies.',
  },
  issuer_kid_mismatch: {
    code: 'issuer_kid_mismatch',
    description: 'An envelope\'s payload names an issuer_id that is not its signature object\'s kid, or names one while the signature object has no kid.',
    class: 'tampered',
    spec: 'draft-farley-acta-signed-receipts-03 §2.2 Payload (issuer_id MUST match the kid); §5.3 Verification Outcomes of the -04 editor\'s copy (VeritasActa/drafts)',
    hint: 'The signed payload names a different issuer from the key identifier beside it. A payload with no issuer_id is reported in payloadNotes and does not change the outcome.',
  },
  schema_invalid: {
    code: 'schema_invalid',
    description: 'The signed payload does not satisfy the required semantic schema for its declared receipt type.',
    class: 'tampered',
    hint: 'The signature may be authentic, but the record is not a valid instance of the declared contract.',
  },

  // --- Undecidable (exit 2) ---
  embedded_key_rejected: {
    code: 'embedded_key_rejected',
    description: 'Receipt contains a verification key in its payload, which is not trusted by default.',
    class: 'undecidable',
    spec: 'draft-farley-acta-signed-receipts-03 §9.5 Key Distribution and Trust Anchors',
    hint: 'Provide --key or --jwks externally. Pass --allow-embedded-key (deprecated, removed in 0.6) to restore pre-0.4.0 behaviour.',
  },
  no_public_key: {
    code: 'no_public_key',
    description: 'No verification key from a trust anchor outside the receipt: none was given with --key or --jwks. An audit bundle\'s own verification.signing_keys are not one, since they arrive in the file being verified (0.10.27).',
    class: 'undecidable',
    hint: 'Provide --key <hex>, or --jwks <url|file>. For an audit bundle, --trust-bundle-keys checks the receipts with the keys it carries, reported as keySource "bundle".',
  },
  missing_signature: {
    code: 'missing_signature',
    description: 'Input does not contain a signature field.',
    class: 'undecidable',
  },
  missing_payload: {
    code: 'missing_payload',
    description: 'Input does not contain a payload field.',
    class: 'undecidable',
  },
  unsupported_algorithm: {
    code: 'unsupported_algorithm',
    description: 'The declared signature algorithm is not supported by this verifier version.',
    class: 'undecidable',
    hint: 'ML-DSA-65, alone or in a hybrid such as ed25519+ml-dsa-65, is not implemented, so a receipt that declares it is undecidable (unsupported_algorithm). Verify it with a verifier that implements the algorithm.',
  },
  unsupported_chain_hash_algorithm: {
    code: 'unsupported_chain_hash_algorithm',
    description: 'previousReceiptHash names a hash algorithm other than sha256, which this verifier does not implement.',
    class: 'undecidable',
    spec: 'draft-farley-acta-signed-receipts-03 §6.7 Chain Hash Scope',
    hint: 'Draft §6.7 requires refusing a link whose prefix names an unimplemented algorithm rather than assuming SHA-256 from its length.',
  },
  malformed_encoding: {
    code: 'malformed_encoding',
    description: 'The receipt could not be encoded or decoded for the signature check: the signature or the key is not valid hexadecimal, or the signed object cannot be canonicalized (a member name that is not ASCII, or a value JCS cannot encode).',
    class: 'undecidable',
    spec: 'RFC 8785 (JCS); AIP-0001 §JCS Canonicalization',
    hint: 'Supply the key as 64 hexadecimal characters, and check that the receipt\'s signature is hexadecimal and its member names are ASCII. Nothing about the signature was established; the detail names the cause.',
  },
  non_ascii_key: {
    code: 'non_ascii_key',
    description: 'An object key contains a non-ASCII character, violating AIP-0001.',
    class: 'undecidable',
    spec: 'AIP-0001 §JCS Canonicalization',
  },
  malformed_json: {
    code: 'malformed_json',
    description: 'Input could not be parsed as JSON.',
    class: 'undecidable',
  },
  malformed_hex: {
    code: 'malformed_hex',
    description: 'A hex-encoded value has odd length or contains invalid characters.',
    class: 'undecidable',
  },
  unknown_format: {
    code: 'unknown_format',
    description: 'Input does not match any recognized receipt, token, or bundle format.',
    class: 'undecidable',
    hint: 'Valid formats: v1 receipt, v2 receipt, Passport envelope, audit bundle, KU bundle, VOPRF token.',
  },
  key_outside_validity_window: {
    code: 'key_outside_validity_window',
    description: 'The receipt was issued outside the signing key\'s valid_from / valid_until window, [valid_from, valid_until).',
    class: 'tampered',
    spec: 'draft-farley-acta-signed-receipts-03 §9.2 Key Compromise',
    hint: 'The key had been rotated out (or was not yet in use) when the receipt says it was issued.',
  },
  key_window_missing: {
    code: 'key_window_missing',
    description: '--require-key-window was given, and the key source carries no validity window for the signing key.',
    class: 'undecidable',
    spec: 'draft-farley-acta-signed-receipts-03 §9.2 Key Compromise',
    hint: 'Publish valid_from / valid_until on the JWK, or verify without --require-key-window (the result then reports key validity as not established).',
  },
  key_window_unverifiable: {
    code: 'key_window_unverifiable',
    description: 'The key source carries a validity window that cannot be applied: a bound that is not an RFC 3339 date-time with its UTC offset written out (null included), bounds in the wrong order, or a receipt whose signed issued_at (an envelope\'s payload.issued_at, a flat receipt\'s issued_at) is missing or is not such a date-time string.',
    class: 'undecidable',
    spec: 'draft-farley-acta-signed-receipts-03 §9.2 Key Compromise',
  },
  disclosure_not_applied: {
    code: 'disclosure_not_applied',
    description: 'A --disclosure-file was given and could not be applied: it cannot be read or parsed, it holds no disclosure, or the receipt\'s signed bytes carry no committed_fields_root to check it against.',
    class: 'undecidable',
    spec: 'draft-farley-acta-signed-receipts-03 §6.5 Selective Disclosure',
    hint: 'The root is read from the signed bytes: an envelope\'s payload, or the top level of a flat receipt. Nothing in the file was verified.',
  },
  jwks_fetch_failed: {
    code: 'jwks_fetch_failed',
    description: 'JWKS endpoint did not return a valid key set, or the key set has no key for the receipt\'s kid.',
    class: 'undecidable',
  },
  context_requirement_unmet: {
    code: 'context_requirement_unmet',
    description: 'One or more --require-context predicates evaluated false at verification time.',
    class: 'undecidable',
    spec: 'Patent #5 claim 2: Live-context verification',
  },
  tier_not_achieved: {
    code: 'tier_not_achieved',
    description: 'Verification succeeded but did not achieve the tier required by --tier.',
    class: 'undecidable',
  },
};

/**
 * @param {string} code
 * @returns {ErrorMeta | undefined}
 */
export function getError(code) {
  return ERROR_REGISTRY[code];
}

/**
 * Map an error code to its process exit code.
 *   0: valid (caller; not in registry)
 *   1: tampered
 *   2: undecidable or unknown error
 *
 * @param {string | undefined} code
 * @returns {1 | 2}
 */
export function exitCodeFor(code) {
  if (!code) return 2;
  const meta = ERROR_REGISTRY[code];
  if (!meta) return 2;
  if (meta.class === 'tampered') return 1;
  return 2;
}
