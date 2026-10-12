/**
 * Canonical error codes emitted by the verifier.
 *
 * Each code has a stable name, human-readable description, spec reference
 * where applicable, and classification (tampered / undecidable) that
 * drives the process exit code.
 *
 * References:
 *   - draft-farley-acta-signed-receipts-03 §Error Codes (informative)
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
    hint: 'A receipt has been inserted, removed, or reordered in the chain.',
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
    spec: 'draft-farley-acta-signed-receipts-03 §VOPRF Token Verification',
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
    description: 'The verification key carried in the record does not match the key pinned with --key.',
    class: 'tampered',
    hint: 'The record was signed by a different identity than the one you required.',
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
    spec: 'draft-farley-acta-signed-receipts-03 §Security Considerations — Key Distribution',
    hint: 'Provide --key, --jwks, or --trust-anchor externally. Pass --allow-embedded-key (deprecated, removed in 0.6) to restore pre-0.4.0 behaviour.',
  },
  no_public_key: {
    code: 'no_public_key',
    description: 'Verification key could not be resolved from --key, --jwks, or bundle verification block.',
    class: 'undecidable',
    hint: 'Provide --key <hex>, --jwks <url>, or --trust-anchor <file>.',
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
    hint: 'Hybrid post-quantum algorithms like ed25519+ml-dsa-65 require v0.6+ for full PQ verification.',
  },
  unsupported_chain_hash_algorithm: {
    code: 'unsupported_chain_hash_algorithm',
    description: 'previousReceiptHash names a hash algorithm other than sha256, which this verifier does not implement.',
    class: 'undecidable',
    spec: 'draft-farley-acta-signed-receipts-03 §6.7 Chain Hash Scope',
    hint: 'Draft §6.7 requires refusing a link whose prefix names an unimplemented algorithm rather than assuming SHA-256 from its length.',
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
    description: 'The key source carries a validity window that cannot be applied: unreadable bounds, or a receipt with no readable issued_at.',
    class: 'undecidable',
    spec: 'draft-farley-acta-signed-receipts-03 §9.2 Key Compromise',
  },
  jwks_fetch_failed: {
    code: 'jwks_fetch_failed',
    description: 'JWKS endpoint did not return a valid key set.',
    class: 'undecidable',
  },
  context_requirement_unmet: {
    code: 'context_requirement_unmet',
    description: 'One or more --require-context predicates evaluated false at verification time.',
    class: 'undecidable',
    spec: 'Patent #5 claim 2 — Live-context verification',
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
 *   0 — valid (caller; not in registry)
 *   1 — tampered
 *   2 — undecidable or unknown error
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
