/**
 * Input format detection.
 *
 * Classifies a parsed JSON object into one of the supported modes:
 *   - 'ed25519-receipt-v1'   — v1 flat artifact (legacy)
 *   - 'ed25519-receipt-v2'   — v2 structured envelope
 *   - 'ed25519-passport'     — Passport envelope ({ payload, signature })
 *   - 'voprf-token'          — VOPRF anonymous credential token
 *   - 'knowledge-unit'       — KU bundle with multiple receipts
 *   - 'ed25519-bundle'       — Audit bundle with signing_keys
 *   - 'selective-disclosure' — receipt with _commitments field
 *   - 'unknown'
 *
 * Detection is structural: checks for marker fields without trying to
 * verify anything. A mode detected here is not a guarantee the payload
 * is valid; it only routes to the right engine.
 *
 * @module verify-cli/src/detect
 * @license Apache-2.0
 */

/**
 * @typedef {Object} DetectResult
 * @property {string} mode          canonical mode identifier
 * @property {string[]} signals     fields observed that led to the classification
 * @property {boolean} hasSelectiveDisclosure
 * @property {boolean} isBundle
 */

/**
 * @param {unknown} input parsed JSON
 * @returns {DetectResult}
 */
export function detectFormat(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return { mode: 'unknown', signals: [], hasSelectiveDisclosure: false, isBundle: false };
  }

  const signals = [];

  // Legacy AIP-0002 selective disclosure (per-field _commitments map).
  const hasLegacyCommitments = input._commitments !== undefined;
  if (hasLegacyCommitments) signals.push('_commitments');

  // draft-farley-acta-signed-receipts-01 §commitment-mode: single
  // committed_fields_root (Merkle root over RFC 6962 domain-separated
  // leaves of {name, salt, value}). Routed to engines/commitment-mode.js,
  // distinct from the legacy AIP-0002 selective-disclosure engine.
  const hasCommittedFieldsRoot =
    typeof input.committed_fields_root === 'string' &&
    input.committed_fields_root.length > 0;
  if (hasCommittedFieldsRoot) signals.push('committed_fields_root');

  // hasSelectiveDisclosure stays true if either format is present (used by
  // CLI dispatch as a feature flag). Engine selection is by signals[].
  const hasSelectiveDisclosure = hasLegacyCommitments || hasCommittedFieldsRoot;

  // Knowledge Unit bundle detection (has ku_id or consensus_level + models_used)
  if (input.type === 'knowledge_unit' || input.ku_id || (input.models_used && input.consensus_level)) {
    signals.push(input.type ? 'type=knowledge_unit' : 'ku_id/consensus_level');
    return { mode: 'knowledge-unit', signals, hasSelectiveDisclosure, isBundle: false };
  }

  // Audit bundle with multiple receipts + signing_keys
  if (Array.isArray(input.receipts) && input.verification?.signing_keys) {
    signals.push('receipts[]', 'verification.signing_keys');
    return { mode: 'ed25519-bundle', signals, hasSelectiveDisclosure, isBundle: true };
  }

  // VOPRF token detection: token value N, DLEQ proofs, scope
  if (input.token || input.N || input.nullifier) {
    signals.push('voprf-marker');
    if (input.proof_I || input.proof_C || input.dleq) signals.push('dleq-proof');
    if (input.scope || (input.origin && input.epoch)) signals.push('scope');
    return { mode: 'voprf-token', signals, hasSelectiveDisclosure: false, isBundle: false };
  }

  // Passport envelope: { payload, signature: { alg, kid, sig } }
  if (input.payload && input.signature && typeof input.signature === 'object'
      && typeof input.signature.sig === 'string'
      && typeof input.signature.alg === 'string') {
    signals.push('payload+signature.alg+signature.sig');
    return { mode: 'ed25519-passport', signals, hasSelectiveDisclosure, isBundle: false };
  }

  // v2 structured envelope: top-level v: 2 + kid + issuer + payload + signature
  if (input.v === 2 && input.kid && input.payload) {
    signals.push('v=2', 'kid', 'payload');
    return { mode: 'ed25519-receipt-v2', signals, hasSelectiveDisclosure, isBundle: false };
  }

  // v1 flat: top-level type + timestamp + signature
  if ((input.v === 1 || input.v === undefined) && input.type && input.signature) {
    signals.push('type', 'signature', input.v === 1 ? 'v=1' : 'no-v');
    return { mode: 'ed25519-receipt-v1', signals, hasSelectiveDisclosure, isBundle: false };
  }

  return { mode: 'unknown', signals, hasSelectiveDisclosure, isBundle: false };
}
