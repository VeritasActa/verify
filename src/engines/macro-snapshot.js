/**
 * ScopeBlind macro-engine snapshot and track-record verifier.
 *
 * The macro engine signs its snapshots (market-state, regime, tape,
 * vulnerability, alert, journal) and its exported track-record bundle with
 * the EXACT same tuple format the Gate uses: { payload, digest, signature,
 * verification_key }, where digest = sha256(canonicalGateJSON(payload)) and
 * signature = Ed25519 over the bytes of the hex digest.
 *
 * These tuples already verify cryptographically through
 * engines/gate-receipt.js verifyGateTuple. This module ADDS:
 *   - recognition of the scopeblind.macro.* schemas,
 *   - a semantic-contract check per schema (macroSchemaErrors),
 *   - a schema-aware salient-field summary for display (macroSummary),
 *   - a track-record BUNDLE verifier (verifyMacroTrackRecord) that mirrors
 *     verifyGateBundle: every record's signature, single-signer custody, an
 *     exact manifest inventory, count checks, and the history_head_digest.
 *
 * No new cryptography is introduced. Crypto is delegated to verifyGateTuple
 * and canonicalization to canonicalGateJSON, both from gate-receipt.js.
 *
 * @module verify-cli/src/engines/macro-snapshot
 * @license Apache-2.0
 */

import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes, bytesToHex } from '@noble/hashes/utils';
import { canonicalGateJSON, verifyGateTuple } from './gate-receipt.js';

export const MACRO_BUNDLE_SCHEMA = 'scopeblind.macro.track-record-bundle/1';
export const MACRO_MANIFEST_SCHEMA = 'scopeblind.macro.track-record-manifest/1';
export const MACRO_ANCHOR_SCHEMA = 'scopeblind.macro.track-record-anchor/1';
export const MACRO_TRANSPARENCY_HEAD_SCHEMA = 'scopeblind.macro.transparency-head/1';
export const MACRO_TRANSPARENCY_WITNESS_SCHEMA = 'scopeblind.macro.transparency-witness/1';
export const MACRO_SCHEMA_PREFIX = 'scopeblind.macro.';

/** Human descriptions for every recognized macro schema. */
export const MACRO_SCHEMAS = {
  'scopeblind.macro.market-state/1': 'daily cross-asset market-state classification',
  'scopeblind.macro.regime-snapshot/1': 'macro regime snapshot from economic series',
  'scopeblind.macro.tape-snapshot/1': 'intraday/session tape attribution snapshot',
  'scopeblind.macro.vulnerability/1': 'book vulnerability decision aid',
  'scopeblind.macro.alert/1': 'state-change alert',
  'scopeblind.macro.journal-entry/1': 'model journal entry referencing snapshots',
  'scopeblind.macro.price-snapshot/1': 'signed point-in-time price levels per risk factor',
  [MACRO_MANIFEST_SCHEMA]: 'signed track-record export manifest',
  [MACRO_ANCHOR_SCHEMA]: 'signed append-only track-record checkpoint',
  [MACRO_TRANSPARENCY_HEAD_SCHEMA]: 'signed RFC 6962 transparency-log head over snapshot digests',
  [MACRO_TRANSPARENCY_WITNESS_SCHEMA]: 'independent witness co-signature over a transparency-log head',
};

const HEX_64 = /^[0-9a-f]{64}$/;
const MARKET_STATE_CLASSES = new Set(['risk_on', 'constructive', 'mixed', 'deteriorating', 'stress']);
const MARKET_STATE_PILLARS = ['trend', 'breadth', 'liquidity', 'credit', 'volatility'];
const REGIMES = new Set(['goldilocks', 'reflation', 'stagflation', 'deflation_bust', 'liquidity_led_recovery', 'tightening_squeeze', 'transitional']);
const TAPE_TYPES = new Set(['credit_stress', 'tightening_shock', 'growth_scare', 'inflation_shock', 'liquidity_risk_on', 'reflation_risk_on', 'mixed']);
const ALERT_SEVERITIES = new Set(['info', 'action', 'critical']);
const ALERT_KINDS = new Set(['regime_transition', 'market_state_change', 'tape_type_change']);

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isString = (v) => typeof v === 'string' && v.length > 0;
const isNumber = (v) => typeof v === 'number' && Number.isFinite(v);
const isInteger = (v) => Number.isInteger(v);
const isArray = (v) => Array.isArray(v);

/** Whether a schema string is a recognized macro snapshot/journal/manifest schema. */
export function isMacroSchema(schema) {
  return typeof schema === 'string' && schema.startsWith(MACRO_SCHEMA_PREFIX);
}

/** A market-state/regime/tape/etc snapshot proves authenticity + integrity + schema validity. */
export const MACRO_PROVES = [
  'Signature integrity: the snapshot verifies under its carried Ed25519 key.',
  'Integrity: neither payload nor digest has been modified since signing.',
  'Schema validity: the recognized macro snapshot satisfies its required semantic contract.',
];
export const MACRO_LIMITATIONS = [
  'The real-world identity controlling the carried key unless the expected key is independently pinned with --key.',
  'Correctness of the underlying market or economic series the snapshot was computed from.',
  'That the classification, regime, or tape attribution is a good or predictive read of the market.',
  'Independent corroboration of the inputs unless separately attested; the model signs what it computed.',
];

export const MACRO_BUNDLE_PROVES = [
  'Signature integrity: every included snapshot, journal entry, manifest, and anchor verifies under one Ed25519 key.',
  'Integrity: no record payload or digest has been modified since signing.',
  'Single-key consistency: all records, including the manifest, share one model verification key.',
  'Manifest completeness: the signed manifest exactly enumerates every exported snapshot and journal entry, in order.',
  'History binding: the manifest history_head_digest commits to the exact ordered set of record digests.',
];
export const MACRO_BUNDLE_LIMITATIONS = [
  'Correctness of the underlying market or economic data the snapshots were computed from.',
  'That the recorded calls were good predictions; the bundle is a tamper-evident track record, not a performance claim.',
  'The real-world identity controlling an embedded key unless the expected key is independently pinned with --key.',
  'Global history completeness unless prior manifests are chained and the latest history/anchor head is independently retained or timestamped.',
];

function requireFields(payload, fields, errors) {
  for (const field of fields) {
    if (payload[field] === undefined || payload[field] === null || payload[field] === '') errors.push(`missing ${field}`);
  }
}

/** Validate an array of { schema, as_of, digest } reference objects with 64-hex digests. */
function refErrors(refs, label, errors, { nonEmpty = true } = {}) {
  if (!isArray(refs)) { errors.push(`${label} must be an array`); return; }
  if (nonEmpty && refs.length === 0) { errors.push(`${label} must be non-empty`); return; }
  for (const ref of refs) {
    if (!isObject(ref) || !isString(ref.schema) || !isString(ref.as_of) || !HEX_64.test(ref.digest || '')) {
      errors.push(`${label} entry must be { schema, as_of, digest(64-hex) }`);
      break;
    }
  }
}

/**
 * Semantic-contract validation for a recognized macro payload.
 * Returns [] for valid payloads and for unrecognized (non-macro or unknown
 * macro) schemas; returns one or more human-readable error strings otherwise.
 *
 * @param {Object} payload signed macro payload
 * @returns {string[]}
 */
export function macroSchemaErrors(payload) {
  const errors = [];
  if (!isObject(payload)) return errors;
  const schema = payload.schema;
  if (!Object.hasOwn(MACRO_SCHEMAS, schema)) return errors;

  if (schema === 'scopeblind.macro.market-state/1') {
    requireFields(payload, ['schema', 'engine_version', 'as_of', 'universe_digest', 'inputs_digest', 'pillars', 'evidence', 'classification', 'confidence', 'would_change', 'notes'], errors);
    if (!MARKET_STATE_CLASSES.has(payload.classification)) errors.push('invalid classification');
    if (!isObject(payload.pillars)) errors.push('pillars must be an object');
    else {
      for (const p of MARKET_STATE_PILLARS) {
        if (!isInteger(payload.pillars[p]) || payload.pillars[p] < -2 || payload.pillars[p] > 2) errors.push(`invalid pillar ${p} (integer in [-2,2])`);
      }
    }
    if (!isNumber(payload.confidence) || payload.confidence < 0 || payload.confidence > 1) errors.push('confidence must be a number in [0,1]');
  } else if (schema === 'scopeblind.macro.regime-snapshot/1') {
    requireFields(payload, ['schema', 'engine_version', 'as_of', 'pillars', 'inputs', 'vintage_digest', 'candidate_regime', 'regime', 'liquidity_overlay', 'hysteresis', 'playbook', 'confidence', 'would_change', 'notes'], errors);
    if (!REGIMES.has(payload.regime)) errors.push('invalid regime');
    if (!REGIMES.has(payload.candidate_regime)) errors.push('invalid candidate_regime');
    if (!HEX_64.test(payload.vintage_digest || '')) errors.push('invalid vintage_digest');
    if (!isObject(payload.pillars)) errors.push('pillars must be an object');
    if (!isArray(payload.inputs)) errors.push('inputs must be an array');
    if (!isNumber(payload.confidence) || payload.confidence < 0 || payload.confidence > 1) errors.push('confidence must be a number in [0,1]');
  } else if (schema === 'scopeblind.macro.tape-snapshot/1') {
    requireFields(payload, ['schema', 'engine_version', 'as_of', 'session', 'tape_type', 'coherence', 'material', 'signals', 'unavailable', 'untestable_types', 'attribution', 'inputs_digest', 'would_change', 'notes'], errors);
    if (!TAPE_TYPES.has(payload.tape_type)) errors.push('invalid tape_type');
    if (!isNumber(payload.coherence) || payload.coherence < 0 || payload.coherence > 1) errors.push('coherence must be a number in [0,1]');
    if (typeof payload.material !== 'boolean') errors.push('material must be a boolean');
    if (!isArray(payload.signals)) errors.push('signals must be an array');
    if (!isObject(payload.attribution) || !isString(payload.attribution.tier)) errors.push('attribution must carry a tier');
  } else if (schema === 'scopeblind.macro.vulnerability/1') {
    requireFields(payload, ['schema', 'engine_version', 'as_of', 'posture', 'factor_exposures', 'betas', 'vulnerabilities', 'inputs_digest', 'would_change', 'notes'], errors);
    if (!isObject(payload.posture)) errors.push('posture must be an object');
    if (!isArray(payload.factor_exposures)) errors.push('factor_exposures must be an array');
    if (!isArray(payload.betas)) errors.push('betas must be an array');
    if (!isArray(payload.vulnerabilities)) errors.push('vulnerabilities must be an array');
  } else if (schema === 'scopeblind.macro.alert/1') {
    requireFields(payload, ['schema', 'engine_version', 'as_of', 'alert_id', 'kind', 'severity', 'title', 'detail', 'refs', 'budget'], errors);
    if (!HEX_64.test(payload.alert_id || '')) errors.push('invalid alert_id');
    if (!ALERT_SEVERITIES.has(payload.severity)) errors.push('invalid severity');
    if (!ALERT_KINDS.has(payload.kind)) errors.push('invalid kind');
    refErrors(payload.refs, 'refs', errors);
  } else if (schema === 'scopeblind.macro.journal-entry/1') {
    requireFields(payload, ['schema', 'engine_version', 'as_of', 'author', 'note', 'references', 'tags'], errors);
    if (!isArray(payload.tags)) errors.push('tags must be an array');
    refErrors(payload.references, 'references', errors);
  } else if (schema === 'scopeblind.macro.price-snapshot/1') {
    requireFields(payload, ['schema', 'engine_version', 'as_of', 'source', 'delay_minutes', 'levels', 'coverage', 'missing', 'notes'], errors);
    if (!isInteger(payload.delay_minutes) || payload.delay_minutes < 0) errors.push('delay_minutes must be a non-negative integer');
    if (!isString(payload.source)) errors.push('source must be a non-empty string');
    if (!isArray(payload.coverage)) errors.push('coverage must be an array');
    if (!isArray(payload.missing)) errors.push('missing must be an array');
    if (!isObject(payload.levels)) {
      errors.push('levels must be an object');
    } else {
      const factors = Object.keys(payload.levels);
      if (factors.length === 0) errors.push('levels must price at least one factor');
      const VALID_UNITS = new Set(['price', 'yield_pct', 'fx_rate', 'spread_bp']);
      for (const f of factors) {
        const lv = payload.levels[f];
        if (!isObject(lv)) { errors.push(`level ${f} must be an object`); continue; }
        if (!isNumber(lv.level)) errors.push(`level ${f} must carry a numeric level`);
        if (!isString(lv.instrument)) errors.push(`level ${f} must name an instrument`);
        if (!VALID_UNITS.has(lv.unit)) errors.push(`level ${f} has invalid unit`);
        if (lv.multiplier !== undefined && (!isNumber(lv.multiplier) || lv.multiplier <= 0)) errors.push(`level ${f} multiplier must be a positive number`);
      }
      // coverage must list exactly the priced factors (sorted), never overstate.
      if (isArray(payload.coverage)) {
        const cov = [...payload.coverage].sort();
        const keys = [...factors].sort();
        if (cov.length !== keys.length || cov.some((c, i) => c !== keys[i])) errors.push('coverage must list exactly the priced factors');
      }
    }
  } else if (schema === MACRO_MANIFEST_SCHEMA) {
    requireFields(payload, ['schema', 'engine_version', 'exported_at', 'model_verification_key', 'period', 'entries', 'snapshot_count', 'journal_count', 'history_head_digest'], errors);
    if (!HEX_64.test(payload.model_verification_key || '')) errors.push('invalid model_verification_key');
    if (!HEX_64.test(payload.history_head_digest || '')) errors.push('invalid history_head_digest');
    refErrors(payload.entries, 'entries', errors, { nonEmpty: false });
    if (payload.sequence !== undefined && (!isInteger(payload.sequence) || payload.sequence < 1)) errors.push('sequence must be a positive integer');
  } else if (schema === MACRO_ANCHOR_SCHEMA) {
    requireFields(payload, ['schema', 'engine_version', 'anchored_at', 'sequence', 'manifest_digest', 'history_head_digest'], errors);
    if (!isInteger(payload.sequence) || payload.sequence < 1) errors.push('sequence must be a positive integer');
    if (!HEX_64.test(payload.manifest_digest || '')) errors.push('invalid manifest_digest');
    if (!HEX_64.test(payload.history_head_digest || '')) errors.push('invalid history_head_digest');
    if (payload.previous_anchor_digest !== null && !HEX_64.test(payload.previous_anchor_digest || '')) errors.push('invalid previous_anchor_digest');
  } else if (schema === MACRO_TRANSPARENCY_HEAD_SCHEMA) {
    requireFields(payload, ['schema', 'engine_version', 'log_id', 'tree_size', 'root_hash', 'timestamp'], errors);
    if (!isInteger(payload.tree_size) || payload.tree_size < 0) errors.push('tree_size must be a non-negative integer');
    if (!HEX_64.test(payload.root_hash || '')) errors.push('invalid root_hash');
    // previous_root_hash is a required key but is null at the genesis head.
    if (!Object.hasOwn(payload, 'previous_root_hash')) errors.push('missing previous_root_hash');
    else if (payload.previous_root_hash !== null && !HEX_64.test(payload.previous_root_hash || '')) errors.push('invalid previous_root_hash');
  } else if (schema === MACRO_TRANSPARENCY_WITNESS_SCHEMA) {
    requireFields(payload, ['schema', 'engine_version', 'head_digest', 'root_hash', 'tree_size', 'witnessed_at', 'note'], errors);
    if (!HEX_64.test(payload.head_digest || '')) errors.push('invalid head_digest');
    if (!HEX_64.test(payload.root_hash || '')) errors.push('invalid root_hash');
    if (!isInteger(payload.tree_size) || payload.tree_size < 0) errors.push('tree_size must be a non-negative integer');
  }
  return errors;
}

/**
 * Extract the salient display fields for a recognized macro snapshot.
 * Returns null for unrecognized schemas.
 *
 * @param {Object} payload signed macro payload
 * @returns {Object|null}
 */
export function macroSummary(payload) {
  if (!isObject(payload) || !Object.hasOwn(MACRO_SCHEMAS, payload.schema)) return null;
  const schema = payload.schema;
  const base = { schema, description: MACRO_SCHEMAS[schema], as_of: payload.as_of };
  if (schema === 'scopeblind.macro.market-state/1') {
    return { ...base, classification: payload.classification, pillars: payload.pillars, confidence: payload.confidence };
  }
  if (schema === 'scopeblind.macro.regime-snapshot/1') {
    return { ...base, regime: payload.regime, candidate_regime: payload.candidate_regime, liquidity_overlay: payload.liquidity_overlay, confidence: payload.confidence };
  }
  if (schema === 'scopeblind.macro.tape-snapshot/1') {
    return { ...base, tape_type: payload.tape_type, coherence: payload.coherence, material: payload.material, attribution_tier: payload.attribution?.tier };
  }
  if (schema === 'scopeblind.macro.vulnerability/1') {
    const top = (isArray(payload.vulnerabilities) ? payload.vulnerabilities : [])
      .slice()
      .sort((a, b) => (b?.pain ?? 0) - (a?.pain ?? 0))
      .slice(0, 3)
      .map((v) => ({ factor: v?.factor, pain: v?.pain }));
    return { ...base, regime: payload.posture?.regime, market_state: payload.posture?.market_state, top_vulnerabilities: top };
  }
  if (schema === 'scopeblind.macro.alert/1') {
    return { ...base, severity: payload.severity, kind: payload.kind, title: payload.title };
  }
  if (schema === 'scopeblind.macro.journal-entry/1') {
    return { ...base, author: payload.author, reference_count: isArray(payload.references) ? payload.references.length : 0, tags: payload.tags };
  }
  if (schema === 'scopeblind.macro.price-snapshot/1') {
    return {
      ...base,
      source: payload.source,
      delay_minutes: payload.delay_minutes,
      priced: isArray(payload.coverage) ? payload.coverage.length : 0,
      missing: isArray(payload.missing) ? payload.missing.length : 0,
    };
  }
  if (schema === MACRO_MANIFEST_SCHEMA) {
    return { ...base, sequence: payload.sequence ?? 1, snapshot_count: payload.snapshot_count, journal_count: payload.journal_count };
  }
  if (schema === MACRO_ANCHOR_SCHEMA) {
    return { ...base, sequence: payload.sequence, manifest_digest: payload.manifest_digest, history_head_digest: payload.history_head_digest };
  }
  if (schema === MACRO_TRANSPARENCY_HEAD_SCHEMA) {
    return { ...base, log_id: payload.log_id, tree_size: payload.tree_size, root_hash: payload.root_hash };
  }
  if (schema === MACRO_TRANSPARENCY_WITNESS_SCHEMA) {
    return { ...base, head_digest: payload.head_digest, tree_size: payload.tree_size };
  }
  return base;
}

const refsEqual = (a, b) =>
  isObject(a) && isObject(b) && a.schema === b.schema && a.as_of === b.as_of && a.digest === b.digest;

// ── RFC 6962 transparency-log inclusion verification ─────────────────
//
// The macro engine signs an RFC 6962 Merkle transparency log over the
// snapshot/journal record digests. This block reconstructs a leaf's root from
// its audit path EXACTLY as the engine builds it, so the verifier can confirm
// that every exported record is committed under the signed head's root_hash.
// Hashing is domain-separated over RAW digest bytes (not the hex string).

/** Decode a hex string to a Uint8Array (no prefix handling; lengths are caller-checked). */
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/** Concatenate Uint8Arrays into one. */
function concatBytes(...arrays) {
  let length = 0;
  for (const a of arrays) length += a.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

/** RFC 6962 leaf hash: sha256(0x00 || raw record-digest bytes). */
function leafHash(recordDigestHex) {
  return sha256(concatBytes(Uint8Array.of(0x00), hexToBytes(recordDigestHex)));
}

/** RFC 6962 interior node hash: sha256(0x01 || left || right). */
function nodeHash(left, right) {
  return sha256(concatBytes(Uint8Array.of(0x01), left, right));
}

/** Largest power of two STRICTLY less than n (RFC 6962 split point). */
function splitPoint(n) {
  let k = 1;
  while ((k << 1) < n) k <<= 1;
  return k;
}

/**
 * Verify an RFC 6962 inclusion proof: reconstruct the Merkle root for the leaf
 * at proof.leaf_index in a tree of proof.tree_size leaves, consuming the audit
 * path deepest-sibling-first (top sibling LAST, i.e. from the END of the array).
 *
 * @param {string} recordDigestHex 64-hex record digest committed as the leaf
 * @param {Object} proof { leaf_index, tree_size, audit_path: string[] }
 * @param {string} expectedRootHex 64-hex root_hash from the signed head
 * @returns {boolean}
 */
export function verifyInclusion(recordDigestHex, proof, expectedRootHex) {
  if (!isObject(proof)) return false;
  const { leaf_index, tree_size, audit_path } = proof;
  if (!isInteger(leaf_index) || !isInteger(tree_size)) return false;
  if (leaf_index < 0 || leaf_index >= tree_size) return false;
  if (!HEX_64.test(recordDigestHex || '')) return false;
  if (!HEX_64.test(expectedRootHex || '')) return false;
  if (!isArray(audit_path) || !audit_path.every((h) => HEX_64.test(h || ''))) return false;
  const nodes = audit_path.map(hexToBytes);

  // hi = number of path nodes still available; the top sibling is nodes[hi-1].
  function root(m, size, hi) {
    if (size === 1) return hi === 0 ? leafHash(recordDigestHex) : null;
    if (hi < 1) return null;
    const k = splitPoint(size);
    const sib = nodes[hi - 1];
    if (m < k) {
      const left = root(m, k, hi - 1);
      return left && nodeHash(left, sib);
    }
    const right = root(m - k, size - k, hi - 1);
    return right && nodeHash(sib, right);
  }

  const r = root(leaf_index, tree_size, nodes.length);
  return r !== null && bytesToHex(r) === expectedRootHex;
}

/**
 * Verify a track-record bundle's transparency evidence: the signed log head,
 * every record's inclusion under that head's root, and (optionally) an
 * independent witness co-signature over the same head.
 *
 * @param {Object} evidence bundle.transparency: { head, witness, inclusions }
 * @param {string[]} recordDigests every snapshot + journal record digest that
 *   must be committed in the log
 * @returns {{ head_valid: boolean, all_included: boolean, witness_present: boolean,
 *   witness_independent: boolean, anchor: 'none'|'self_signed'|'witnessed',
 *   tree_size: number|null, root_hash: string|null, errors: string[] }}
 */
export function verifyTransparencyEvidence(evidence, recordDigests = []) {
  const result = {
    head_valid: false,
    all_included: false,
    witness_present: false,
    witness_independent: false,
    anchor: 'none',
    tree_size: null,
    root_hash: null,
    errors: [],
  };
  if (!isObject(evidence) || !isObject(evidence.head)) {
    result.errors.push('transparency evidence is missing a signed head');
    return result;
  }

  const head = evidence.head;
  const headResult = verifyGateTuple(head);
  const headPayload = isObject(head.payload) ? head.payload : {};
  const root = headPayload.root_hash;
  result.tree_size = isInteger(headPayload.tree_size) ? headPayload.tree_size : null;
  result.root_hash = isString(root) ? root : null;

  if (!headResult.valid) {
    result.errors.push(`transparency head signature invalid: ${headResult.error}`);
  } else if (headPayload.schema !== MACRO_TRANSPARENCY_HEAD_SCHEMA) {
    result.errors.push('transparency head is not a transparency-head schema');
  } else if (!HEX_64.test(root || '')) {
    result.errors.push('transparency head root_hash is not 64-hex');
  } else {
    result.head_valid = true;
  }

  // Inclusion of every checked record under the signed root.
  if (result.head_valid) {
    const inclusions = isArray(evidence.inclusions) ? evidence.inclusions : [];
    const byDigest = new Map();
    for (const inc of inclusions) {
      if (isObject(inc) && isString(inc.digest)) byDigest.set(inc.digest.toLowerCase(), inc);
    }
    let allIncluded = recordDigests.length > 0 || inclusions.length > 0;
    for (const digest of recordDigests) {
      const inc = byDigest.get(String(digest).toLowerCase());
      if (!inc || !verifyInclusion(digest, inc.proof, root)) {
        allIncluded = false;
        result.errors.push(`record ${String(digest).slice(0, 16)}... is not provably included in the signed log`);
      }
    }
    result.all_included = allIncluded;
  }

  // Optional independent witness co-signature over the same head.
  if (isObject(evidence.witness)) {
    result.witness_present = true;
    const witness = evidence.witness;
    const witnessResult = verifyGateTuple(witness);
    const witnessPayload = isObject(witness.payload) ? witness.payload : {};
    const witnessValid = witnessResult.valid
      && witnessPayload.schema === MACRO_TRANSPARENCY_WITNESS_SCHEMA
      && witnessPayload.head_digest === head.digest
      && witnessPayload.root_hash === root;
    if (!witnessValid) {
      result.errors.push('transparency witness does not co-sign this head');
    } else {
      result.witness_independent = isString(witness.verification_key)
        && isString(head.verification_key)
        && witness.verification_key.toLowerCase() !== head.verification_key.toLowerCase();
    }
  }

  result.anchor = (!result.head_valid || !result.all_included)
    ? 'none'
    : result.witness_independent ? 'witnessed' : 'self_signed';
  return result;
}

/**
 * Verify a macro track-record bundle.
 *
 * Mirrors verifyGateBundle: it checks each record's signature, that every
 * record (including the manifest) is signed by the single declared model
 * key, that the manifest entries exactly enumerate the snapshots followed by
 * the journal entries in order, the snapshot/journal counts, and that the
 * history_head_digest recomputes over the ordered record digests.
 *
 * @param {Object} bundle parsed track-record bundle
 * @param {Object} [opts] { publicKey } optional pinned model key
 * @returns {Object} result with the same error-shape conventions as gate-receipt.js
 */
export function verifyMacroTrackRecord(bundle, opts = {}) {
  const results = {
    valid: true,
    format: 'macro-track-record',
    schema: bundle?.schema,
    exportedAt: bundle?.exported_at,
    period: isObject(bundle?.period) ? bundle.period : null,
    custody: isString(bundle?.custody) ? bundle.custody : null,
    modelVerificationKey: isString(bundle?.model_verification_key) ? bundle.model_verification_key : null,
    snapshotCount: 0,
    journalCount: 0,
    total: 0,
    passed: 0,
    failed: 0,
    cryptoFailed: 0,
    chainChecks: 0,
    chainFailed: 0,
    errors: [],
    records: [],
    signers: [],
    singleSigner: true,
    manifestValid: null,
    signerPinned: isString(opts.publicKey),
    identityStatus: isString(opts.publicKey) ? 'pinned_operator_key' : 'embedded_key_only',
    historyChainValid: null,
    historyAnchored: false,
    historyHeadPinned: false,
    anchorHeadPinned: false,
    sequence: 1,
    transparencyAnchor: null,
    proves: MACRO_BUNDLE_PROVES,
    limitations: MACRO_BUNDLE_LIMITATIONS,
  };

  if (!isObject(bundle) || bundle.schema !== MACRO_BUNDLE_SCHEMA || !isArray(bundle.snapshots) || !isObject(bundle.manifest)) {
    return { ...results, valid: false, error: 'unknown_format', detail: 'unsupported macro bundle schema or missing snapshots/manifest' };
  }

  const snapshots = bundle.snapshots;
  const journal = isArray(bundle.journal) ? bundle.journal : [];
  const priorManifests = isArray(bundle.prior_manifests) ? bundle.prior_manifests : [];
  const anchors = isArray(bundle.anchor_chain) ? bundle.anchor_chain : [];
  results.snapshotCount = snapshots.length;
  results.journalCount = journal.length;

  if (!HEX_64.test(results.modelVerificationKey || '')) {
    return { ...results, valid: false, error: 'no_public_key', detail: 'bundle requires model_verification_key' };
  }
  const modelKey = results.modelVerificationKey.toLowerCase();
  if (isString(opts.publicKey) && opts.publicKey.toLowerCase() !== modelKey) {
    return { ...results, valid: false, error: 'key_mismatch', detail: 'bundle model_verification_key does not match --key' };
  }

  const signerRoles = new Map();
  let firstError = null;

  const add = (tuple, role, index) => {
    results.total++;
    const r = verifyGateTuple(tuple, { publicKey: modelKey });
    const key = isString(tuple?.verification_key) ? tuple.verification_key.toLowerCase() : null;
    if (key) {
      if (!signerRoles.has(key)) signerRoles.set(key, new Set());
      signerRoles.get(key).add(role);
      if (key !== modelKey) results.singleSigner = false;
    } else {
      results.singleSigner = false;
    }
    const record = {
      index: index + 1,
      role,
      schema: r.schema,
      schemaRecognized: r.schemaRecognized || isMacroSchema(r.schema),
      cryptoValid: r.valid,
      cryptoError: r.valid ? undefined : r.error,
      signer: tuple?.verification_key,
      digest: tuple?.digest,
    };
    results.records.push(record);
    if (!r.valid) {
      results.cryptoFailed++;
      results.valid = false;
      firstError ||= r.error;
      results.errors.push(`[crypto] ${role} ${index + 1}: ${r.error}${r.detail ? ` (${r.detail})` : ''}`);
      results.failed++;
    } else {
      results.passed++;
    }
    return r;
  };

  for (let i = 0; i < snapshots.length; i++) add(snapshots[i], 'snapshot', i);
  for (let i = 0; i < journal.length; i++) add(journal[i], 'journal', i);
  for (let i = 0; i < priorManifests.length; i++) add(priorManifests[i], 'prior-manifest', i);
  const mr = add(bundle.manifest, 'manifest', -1);
  for (let i = 0; i < anchors.length; i++) add(anchors[i], 'history-anchor', i);
  results.manifestValid = mr.valid;

  // Single-signer custody check (every record, including the manifest, shares
  // the declared model key).
  results.chainChecks++;
  if (!results.singleSigner) {
    results.valid = false;
    results.chainFailed++;
    results.errors.push('[chain] not all records are signed by model_verification_key (single-signer custody violated)');
  }

  // Manifest inventory + counts + history head.
  if (mr.valid) {
    const p = bundle.manifest.payload;
    const ordered = [...snapshots, ...journal];
    const expectedEntries = ordered.map((t) => ({ schema: t?.payload?.schema, as_of: t?.payload?.as_of, digest: t?.digest }));
    const historyHead = bytesToHex(sha256(utf8ToBytes(canonicalGateJSON(ordered.map((t) => t?.digest)))));

    results.chainChecks++;
    const entries = isArray(p.entries) ? p.entries : [];
    let manifestError = null;
    if (p.model_verification_key?.toLowerCase() !== modelKey) manifestError = 'manifest model_verification_key mismatch';
    else if (p.exported_at !== bundle.exported_at) manifestError = 'manifest exported_at mismatch';
    else if (entries.length !== expectedEntries.length) manifestError = `manifest entries count (${entries.length}) does not match exported records (${expectedEntries.length})`;
    else if (!entries.every((e, idx) => refsEqual(e, expectedEntries[idx]))) manifestError = 'manifest entries do not exactly enumerate the exported records in order';
    else if (p.snapshot_count !== snapshots.length) manifestError = `manifest snapshot_count (${p.snapshot_count}) does not match (${snapshots.length})`;
    else if (p.journal_count !== journal.length) manifestError = `manifest journal_count (${p.journal_count}) does not match (${journal.length})`;
    else if (p.history_head_digest !== historyHead) manifestError = 'manifest history_head_digest mismatch';
    else if (p.sequence !== undefined && (!isInteger(p.sequence) || p.sequence < 1)) manifestError = 'manifest sequence is not a positive integer';

    if (manifestError) {
      results.valid = false;
      results.manifestValid = false;
      results.chainFailed++;
      results.errors.push(`[chain] Manifest: ${manifestError}`);
    }

    results.sequence = p.sequence ?? 1;
    results.chainChecks++;
    if (isString(opts.historyHead)) {
      results.historyHeadPinned = opts.historyHead.toLowerCase() === String(p.history_head_digest).toLowerCase();
      if (!results.historyHeadPinned) {
        results.valid = false;
        results.chainFailed++;
        results.errors.push('[chain] current history head does not match --history-head');
      }
    }

    const manifests = [...priorManifests, bundle.manifest];
    let historyChainError = null;
    if (priorManifests.length > 0 || p.sequence !== undefined) {
      const retained = new Set(expectedEntries.map((entry) => entry.digest));
      for (let i = 0; i < manifests.length && !historyChainError; i++) {
        const current = manifests[i];
        const payload = current?.payload;
        const expectedSequence = i + 1;
        if ((payload?.sequence ?? expectedSequence) !== expectedSequence) {
          historyChainError = `manifest sequence mismatch at ${expectedSequence}`;
          break;
        }
        if (i > 0) {
          const previous = manifests[i - 1];
          if (payload?.previous_manifest_digest !== previous?.digest
            || payload?.previous_history_head_digest !== previous?.payload?.history_head_digest) {
            historyChainError = `manifest previous-head mismatch at sequence ${expectedSequence}`;
            break;
          }
        }
        for (const entry of (isArray(payload?.entries) ? payload.entries : [])) {
          if (!retained.has(entry.digest)) {
            historyChainError = `current export omits prior record ${entry.digest}`;
            break;
          }
        }
      }
      results.historyChainValid = historyChainError === null;
      results.chainChecks++;
      if (historyChainError) {
        results.valid = false;
        results.chainFailed++;
        results.errors.push(`[chain] History: ${historyChainError}`);
      }
    }

    if (anchors.length > 0) {
      results.historyAnchored = true;
      const offset = manifests.length - anchors.length;
      let anchorError = null;
      for (let i = 0; i < anchors.length && !anchorError; i++) {
        const anchor = anchors[i];
        const anchorPayload = anchor?.payload;
        const manifest = manifests[offset + i];
        if (!manifest) {
          anchorError = `anchor ${i + 1} has no corresponding manifest`;
          break;
        }
        const previousAnchor = i > 0 ? anchors[i - 1]?.digest : null;
        if (anchorPayload?.schema !== MACRO_ANCHOR_SCHEMA
          || anchorPayload?.sequence !== manifest.payload?.sequence
          || anchorPayload?.manifest_digest !== manifest.digest
          || anchorPayload?.history_head_digest !== manifest.payload?.history_head_digest
          || anchorPayload?.previous_anchor_digest !== previousAnchor) {
          anchorError = `anchor mismatch at sequence ${anchorPayload?.sequence ?? i + 1}`;
        }
      }
      results.chainChecks++;
      if (anchorError) {
        results.valid = false;
        results.chainFailed++;
        results.errors.push(`[chain] Anchor: ${anchorError}`);
      }
      const anchorHead = anchors.at(-1)?.digest;
      if (isString(opts.anchorHead)) {
        results.anchorHeadPinned = opts.anchorHead.toLowerCase() === String(anchorHead).toLowerCase();
        results.chainChecks++;
        if (!results.anchorHeadPinned) {
          results.valid = false;
          results.chainFailed++;
          results.errors.push('[chain] current anchor head does not match --anchor-head');
        }
      }
    }
  } else {
    // Manifest signature failed; inventory cannot be trusted.
    results.chainChecks++;
    results.chainFailed++;
    results.valid = false;
    results.errors.push('[chain] Manifest signature invalid; inventory cannot be verified');
  }

  // Optional RFC 6962 transparency evidence: confirm every exported record
  // digest is committed under a signed (and optionally witnessed) log head.
  // A bundle WITHOUT a transparency field stays valid (backward compatible).
  if (isObject(bundle.transparency)) {
    const recordDigests = [...snapshots, ...journal]
      .map((t) => (isString(t?.digest) ? t.digest : null))
      .filter(Boolean);
    const transparency = verifyTransparencyEvidence(bundle.transparency, recordDigests);
    results.transparencyAnchor = transparency;
    results.chainChecks++;
    if (!transparency.head_valid || !transparency.all_included) {
      results.valid = false;
      results.chainFailed++;
      const why = !transparency.head_valid
        ? 'transparency head is not a valid signed log head'
        : 'one or more exported records are not provably included in the signed log';
      results.errors.push(`[chain] Transparency: ${why}${transparency.errors.length ? ` (${transparency.errors[0]})` : ''}`);
    }
  }

  results.signers = [...signerRoles.entries()].map(([key, roles]) => ({ key, roles: [...roles].sort(), isModelKey: key === modelKey }));
  if (!results.valid) results.error = firstError || 'chain_link_mismatch';
  return results;
}
