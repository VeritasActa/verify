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
 *   - 'gate-receipt-tuple'   — ScopeBlind Gate tuple ({ payload, digest, signature, verification_key })
 *   - 'gate-evidence-bundle' — ScopeBlind Gate evidence bundle (scopeblind.gate.evidence-bundle/2)
 *   - 'macro-track-record'   — ScopeBlind macro-engine track-record bundle (scopeblind.macro.track-record-bundle/1)
 *   - 'legate-standard'      — Legate signed standard, recipient decision, or action assurance bundle
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

  // ScopeBlind Verifiable Claims v2.1.1 protocol artifacts. Detection is type
  // locked and precedes the generic flat-receipt fallback.
  if (
    typeof input.type === 'string'
    && new Set([
      'scopeblind.claim_contract.v2',
      'scopeblind.claims_conformance_manifest.v1',
      'scopeblind.trust_policy.v2',
      'scopeblind.trust_snapshot.v1',
      'scopeblind.claim_verification_report.v2',
      'scopeblind.recipient_reliance_decision.v3',
    ]).has(input.type)
  ) {
    signals.push(`type=${input.type}`);
    return { mode: 'scopeblind-claims-v2.1.1', signals, hasSelectiveDisclosure: false, isBundle: false };
  }

  // Legate standard files: type locked, ahead of the generic receipt fallbacks.
  if (
    typeof input.type === 'string'
    && new Set([
      'scopeblind.proof_request.v1',
      'scopeblind.admission_decision.v1',
      'scopeblind.action_assurance_bundle.v1',
      'scopeblind.presentation.v1',
      'scopeblind.effect_readback.v1',
      'scopeblind.anchor_witness.v1',
    ]).has(input.type)
  ) {
    signals.push(`type=${input.type}`);
    return { mode: 'legate-standard', signals, hasSelectiveDisclosure: false, isBundle: input.type === 'scopeblind.action_assurance_bundle.v1' };
  }

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

  // ScopeBlind Gate evidence bundle: explicit schema marker + entries[].
  if (/^scopeblind\.gate\.evidence-bundle\/[12]$/.test(input.schema) && Array.isArray(input.entries)) {
    signals.push(`schema=${input.schema}`, 'entries[]');
    return { mode: 'gate-evidence-bundle', signals, hasSelectiveDisclosure: false, isBundle: true };
  }

  // ScopeBlind macro-engine track-record bundle: explicit schema marker +
  // snapshots[] + a signed manifest tuple.
  if (
    input.schema === 'scopeblind.macro.track-record-bundle/1'
    && Array.isArray(input.snapshots)
    && input.manifest && typeof input.manifest === 'object' && !Array.isArray(input.manifest)
  ) {
    signals.push(`schema=${input.schema}`, 'snapshots[]', 'manifest');
    return { mode: 'macro-track-record', signals, hasSelectiveDisclosure: false, isBundle: true };
  }

  // ScopeBlind Trusted Context Pack: a Gate-tuple-shaped envelope whose payload
  // carries the TCB schema marker. Detected BEFORE the generic gate tuple (it
  // matches that shape too) and routed to engines/trusted-context-pack.js so a
  // third party re-verifies the parsed-context attestation, its confidence, and
  // its gate decision offline.
  if (
    input.payload && typeof input.payload === 'object' && !Array.isArray(input.payload)
    && input.payload.schema === 'scopeblind.trusted_context_pack.v1'
    && typeof input.digest === 'string'
    && typeof input.signature === 'string'
    && typeof input.verification_key === 'string'
  ) {
    signals.push('schema=scopeblind.trusted_context_pack.v1');
    return { mode: 'trusted-context-pack', signals, hasSelectiveDisclosure: false, isBundle: false };
  }

  // ScopeBlind Gate receipt tuple: { payload, digest, signature, verification_key }.
  // The flat hex signature string distinguishes it from the Passport
  // envelope (object signature); the digest + verification_key fields
  // distinguish it from v1/v2 receipts.
  if (
    input.payload && typeof input.payload === 'object' && !Array.isArray(input.payload)
    && typeof input.digest === 'string' && /^[0-9a-f]{64}$/.test(input.digest)
    && typeof input.signature === 'string'
    && typeof input.verification_key === 'string'
  ) {
    signals.push('payload+digest+signature+verification_key');
    return { mode: 'gate-receipt-tuple', signals, hasSelectiveDisclosure: false, isBundle: false };
  }

  // Legate adherence / restraint proof pack: type scopeblind.legate.proof-pack.v1,
  // signed by the runtime key (verification_key) over the canonical bytes of the pack
  // minus signature/sha256. A position-blind record of what the gate prevented (held /
  // blocked, by rule) plus order-path shadow evidence. Detected before the v1-flat
  // catch-all so it routes to engines/legate-proof-pack.js. Routed by its type.
  if (
    input.type === 'scopeblind.legate.proof-pack.v1'
    && typeof input.signature === 'string'
    && (typeof input.verification_key === 'string'
        || (input.runtime && typeof input.runtime.verification_key === 'string'))
  ) {
    signals.push('type=scopeblind.legate.proof-pack.v1', 'signature+verification_key');
    return { mode: 'legate-proof-pack', signals, hasSelectiveDisclosure: false, isBundle: false };
  }

  // Legate governed receipt: a FLAT, pipe-delimited canonical payload
  //   scopeblind.receipt.v1|<id>|<tool>|<decision>|<input_sha256>|<result_sha256>|<at>
  // co-signed by the desktop daemon and the iPhone. Distinguished from the Gate
  // tuple by the ABSENCE of a payload object and a digest, and from a v1 flat
  // receipt by carrying tool + input_sha256 + result_sha256 alongside a flat hex
  // signature and verification_key. Routed to engines/legate-governed-receipt.js
  // so a third party re-verifies the exact bytes the daemon and phone signed.
  if (
    input.payload === undefined && input.digest === undefined
    && typeof input.tool === 'string' && input.tool.length > 0
    && typeof input.input_sha256 === 'string'
    && typeof input.result_sha256 === 'string'
    && typeof input.signature === 'string'
    && typeof input.verification_key === 'string'
  ) {
    signals.push('tool+input_sha256+result_sha256+signature+verification_key');
    return { mode: 'legate-governed-receipt', signals, hasSelectiveDisclosure: false, isBundle: false };
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
