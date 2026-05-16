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
    spec: 'draft-farley-acta-signed-receipts-03 §6.1',
    hint: 'The receipt has been modified or signed by a different key than the one provided.',
  },
  chain_break: {
    code: 'chain_break',
    description: 'previousReceiptHash does not match the hash of the preceding receipt.',
    class: 'tampered',
    spec: 'draft-farley-acta-signed-receipts-03 §5.4 Chain Linkage',
    hint: 'A receipt has been inserted, removed, or reordered in the chain.',
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
