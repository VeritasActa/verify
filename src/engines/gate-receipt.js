/** ScopeBlind Gate receipt and evidence-bundle verifier. */
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
import { sortKeysDeep } from '../util/canonical.js';
import { hexToBytes, bytesToHex } from '../util/hex.js';
import { isMacroSchema, macroSchemaErrors, macroSummary, MACRO_PROVES, MACRO_LIMITATIONS } from './macro-snapshot.js';

export const GATE_BUNDLE_SCHEMA = 'scopeblind.gate.evidence-bundle/2';
export const GATE_SCHEMAS = {
  'scopeblind.gate.decision/2': 'single order decision',
  'scopeblind.gate.batch/1': 'batch decision',
  'scopeblind.gate.batch-leg/1': 'batch leg',
  'scopeblind.gate.approval/1': 'PM approval',
  'scopeblind.gate.fill/1': 'legacy fill',
  'scopeblind.gate.fill/2': 'execution fill',
  'scopeblind.gate.order-state/1': 'held remainder authority state',
  'scopeblind.gate.evidence-manifest/1': 'signed bundle manifest',
  'scopeblind.gate.reconciliation/1': 'custodian-statement reconciliation',
  'scopeblind.gate.stress/1': 'regime stress-test result',
  'scopeblind.mandate.delegation/1': 'issuer-signed mandate delegation',
};

const HEX_64 = /^[0-9a-f]{64}$/;
const DECISIONS = new Set(['ALLOW', 'APPROVAL_REQUIRED', 'DENY', 'REVIEW']);
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isString = (v) => typeof v === 'string' && v.length > 0;
const isNumber = (v) => typeof v === 'number' && Number.isFinite(v);
const same = (a, b) => canonicalGateJSON(a) === canonicalGateJSON(b);

export function canonicalGateJSON(payload) {
  return JSON.stringify(sortKeysDeep(payload));
}

export const GATE_PROVES = [
  'Authenticity: each record was signed by the Ed25519 key attributed to its role.',
  'Integrity: neither payload nor digest has been modified since signing.',
  'Schema validity: recognized records satisfy their required semantic contract.',
];
export const GATE_BUNDLE_PROVES = GATE_PROVES.concat([
  'Exact chain consistency: child content matches the signed parent, not only its digest.',
  'Manifest completeness: the signed manifest exactly enumerates every exported record.',
]);
export const GATE_LIMITATIONS = [
  'Correctness of the underlying risk inputs or external market data unless separately attested.',
  'Independent execution corroboration when a fill source explicitly identifies itself as a same-browser demo key.',
  'Global history completeness beyond the manifest scope; the exporter signs what it claims was retained at export time.',
];

function requireFields(payload, fields, errors) {
  for (const field of fields) if (payload[field] === undefined || payload[field] === null || payload[field] === '') errors.push(`missing ${field}`);
}

function schemaErrors(payload) {
  const errors = [];
  const schema = payload.schema;
  if (!Object.hasOwn(GATE_SCHEMAS, schema)) return errors;
  if (schema === 'scopeblind.gate.decision/2') {
    requireFields(payload, ['proposal_id', 'proposal', 'decision', 'mandate_digest', 'book_digest', 'nav', 'evaluated_at'], errors);
    if (!DECISIONS.has(payload.decision)) errors.push('invalid decision');
    if (!isObject(payload.proposal) || !isString(payload.proposal.symbol) || !['buy', 'sell'].includes(payload.proposal.side) || !(payload.proposal.qty > 0)) errors.push('invalid proposal');
  } else if (schema === 'scopeblind.gate.batch/1') {
    requireFields(payload, ['batch_id', 'decision', 'legs', 'mandate_digest', 'book_digest', 'post_book_digest', 'nav', 'evaluated_at'], errors);
    if (!DECISIONS.has(payload.decision)) errors.push('invalid decision');
    if (!Array.isArray(payload.legs) || payload.legs.length === 0) errors.push('legs must be non-empty');
    else {
      const ids = new Set();
      for (const leg of payload.legs) {
        if (!isObject(leg) || !isString(leg.leg_id) || !isString(leg.symbol) || !['buy', 'sell'].includes(leg.side) || !(leg.qty > 0)) errors.push('invalid parent leg summary');
        if (ids.has(leg?.leg_id)) errors.push(`duplicate parent leg_id ${leg?.leg_id}`);
        ids.add(leg?.leg_id);
      }
    }
  } else if (schema === 'scopeblind.gate.batch-leg/1') {
    requireFields(payload, ['batch_id', 'batch_receipt_digest', 'leg_id', 'symbol', 'side', 'qty', 'decision', 'evaluated_at'], errors);
    if (!HEX_64.test(payload.batch_receipt_digest || '')) errors.push('invalid batch_receipt_digest');
    if (!['buy', 'sell'].includes(payload.side) || !(payload.qty > 0) || !DECISIONS.has(payload.decision)) errors.push('invalid leg semantics');
  } else if (schema === 'scopeblind.gate.approval/1') {
    requireFields(payload, ['evaluation_digest', 'scope', 'subject', 'decision', 'approver', 'decided_at'], errors);
    if (!HEX_64.test(payload.evaluation_digest || '')) errors.push('invalid evaluation_digest');
    if (!['approved', 'declined'].includes(payload.decision)) errors.push('invalid approval decision');
    if (!['basket', 'order'].includes(payload.scope)) errors.push('invalid approval scope');
  } else if (schema === 'scopeblind.gate.fill/1' || schema === 'scopeblind.gate.fill/2') {
    requireFields(payload, ['batch_receipt_digest', 'leg_id', 'symbol', 'side', 'qty_ordered', 'qty_filled', 'status', 'filled_at', 'source'], errors);
    if (!['filled', 'partial'].includes(payload.status) || !['buy', 'sell'].includes(payload.side)) errors.push('invalid fill semantics');
    if (!(payload.qty_ordered > 0) || !(payload.qty_filled >= 0) || payload.qty_filled > payload.qty_ordered) errors.push('invalid fill quantities');
    if (payload.status === 'filled' && payload.qty_filled !== payload.qty_ordered) errors.push('filled status requires full quantity');
    if (payload.status === 'partial' && !(payload.qty_filled < payload.qty_ordered)) errors.push('partial status requires a remainder');
    if (schema.endsWith('/2')) {
      requireFields(payload, ['batch_id', 'leg_receipt_digest', 'client_order_id', 'external_order_id', 'execution_id', 'fill_id', 'account', 'venue', 'currency', 'remaining_qty', 'remaining_authority'], errors);
      if (payload.remaining_qty !== payload.qty_ordered - payload.qty_filled) errors.push('remaining_qty arithmetic mismatch');
      if (payload.remaining_authority !== 'none') errors.push('remaining_authority must be none');
      if (!isObject(payload.source)) errors.push('invalid fill source');
      else {
        requireFields(payload.source, ['name', 'independence', 'verification_key', 'trust'], errors);
        if (!HEX_64.test(payload.source.verification_key || '')) errors.push('invalid source key');
      }
    }
  } else if (schema === 'scopeblind.gate.order-state/1') {
    requireFields(payload, ['batch_id', 'batch_receipt_digest', 'leg_receipt_digest', 'fill_receipt_digest', 'leg_id', 'client_order_id', 'state', 'remaining_qty', 'authorized_remaining_qty', 'requires_new_decision', 'recorded_at'], errors);
    if (payload.state !== 'partially_filled_remainder_held' || !(payload.remaining_qty > 0) || payload.authorized_remaining_qty !== 0 || payload.requires_new_decision !== true) errors.push('order state does not fail closed');
  } else if (schema === 'scopeblind.gate.evidence-manifest/1') {
    requireFields(payload, ['bundle_id', 'exported_at', 'completeness', 'gate_verification_key', 'entries', 'record_count', 'history_head_digest'], errors);
    if (!Array.isArray(payload.entries)) errors.push('manifest entries must be an array');
    if (!isObject(payload.completeness) || !isString(payload.completeness.scope) || !isString(payload.completeness.definition)) errors.push('invalid completeness definition');
  } else if (schema === 'scopeblind.mandate.delegation/1') {
    requireFields(payload, ['delegation_id', 'parent_mandate_digest', 'child_mandate_digest', 'holder_verification_key', 'issuer_verification_key', 'scope', 'issued_at', 'expires_at', 'nonce', 'revocation'], errors);
    if (!HEX_64.test(payload.parent_mandate_digest || '') || !HEX_64.test(payload.child_mandate_digest || '') || !HEX_64.test(payload.holder_verification_key || '') || !HEX_64.test(payload.issuer_verification_key || '')) errors.push('invalid delegation digest or key');
    if (payload.scope?.principal !== 'Agent::pm' || payload.scope?.action !== 'Action::trade' || payload.scope?.resource !== 'Portfolio::main') errors.push('invalid delegation scope');
    if (Date.parse(payload.expires_at) <= Date.parse(payload.issued_at)) errors.push('invalid delegation expiry');
    if (payload.revocation?.status !== 'not_revoked' || !isString(payload.revocation?.reference)) errors.push('invalid revocation reference');
  }
  return errors;
}

function collectGatePayloadFields(payload) {
  const fields = {};
  for (const k of ['schema', 'decision', 'proposal_id', 'batch_id', 'kind', 'leg_id', 'client_order_id', 'external_order_id', 'execution_id', 'fill_id', 'symbol', 'side', 'qty', 'qty_ordered', 'qty_filled', 'remaining_qty', 'status', 'scope', 'subject', 'nav', 'mandate_digest', 'book_digest', 'post_book_digest', 'evaluated_at', 'decided_at', 'filled_at']) {
    if (payload[k] !== undefined && payload[k] !== null) fields[k] = payload[k];
  }
  if (Array.isArray(payload.determining)) fields.determining = payload.determining;
  if (Array.isArray(payload.legs)) fields.leg_count = payload.legs.length;
  return fields;
}

function collectGateChainFields(payload) {
  const links = {};
  for (const k of ['batch_receipt_digest', 'leg_receipt_digest', 'fill_receipt_digest', 'evaluation_digest']) if (isString(payload[k])) links[k] = payload[k];
  if (isString(payload.leg_id)) links.leg_id = payload.leg_id;
  return Object.keys(links).length ? links : null;
}

export function verifyGateTuple(tuple, opts = {}) {
  const base = { format: 'gate-tuple', schema: null, schemaRecognized: false };
  if (!isObject(tuple)) return { valid: false, error: 'unknown_format', ...base, detail: 'tuple is not an object' };
  const payload = tuple.payload;
  if (!isObject(payload)) return { valid: false, error: 'missing_payload', ...base };
  const schema = isString(payload.schema) ? payload.schema : null;
  const macro = schema !== null && isMacroSchema(schema);
  const schemaRecognized = schema !== null && (Object.hasOwn(GATE_SCHEMAS, schema) || macro);
  Object.assign(base, { schema, schemaRecognized, macroSchema: macro, type: schema || undefined, payloadFields: collectGatePayloadFields(payload), chainFields: macro ? null : collectGateChainFields(payload) });
  if (macro) base.macroSummary = macroSummary(payload);
  if (!isString(tuple.signature)) return { valid: false, error: 'missing_signature', ...base };
  if (!isString(tuple.digest) || !HEX_64.test(tuple.digest)) return { valid: false, error: 'malformed_hex', ...base, detail: 'tuple digest must be 64 lowercase hex characters' };
  if (!isString(tuple.verification_key)) return { valid: false, error: 'no_public_key', ...base };
  const pinned = isString(opts.publicKey);
  if (pinned && opts.publicKey.toLowerCase() !== tuple.verification_key.toLowerCase()) return { valid: false, error: 'key_mismatch', ...base, publicKey: tuple.verification_key, expectedKey: opts.publicKey };
  const recomputed = bytesToHex(sha256(utf8ToBytes(canonicalGateJSON(payload))));
  if (recomputed !== tuple.digest) return { valid: false, error: 'digest_mismatch', ...base, digest: tuple.digest, recomputedDigest: recomputed, publicKey: tuple.verification_key };
  try {
    if (!ed25519.verify(hexToBytes(tuple.signature), hexToBytes(tuple.digest), hexToBytes(tuple.verification_key))) return { valid: false, error: 'invalid_signature', ...base, digest: tuple.digest, publicKey: tuple.verification_key };
  } catch (e) {
    return { valid: false, error: 'malformed_hex', ...base, digest: tuple.digest, detail: e.message };
  }
  const semanticErrors = macro ? macroSchemaErrors(payload) : schemaErrors(payload);
  if (semanticErrors.length) return { valid: false, error: 'schema_invalid', ...base, digest: tuple.digest, publicKey: tuple.verification_key, detail: semanticErrors.join('; '), semanticErrors };
  return {
    valid: true,
    ...base,
    digest: tuple.digest,
    publicKey: tuple.verification_key,
    keySource: pinned ? 'embedded-tuple (pinned via --key)' : 'embedded-tuple',
    signerPinned: pinned,
    identityStatus: pinned ? 'pinned_expected_key' : 'embedded_key_only',
    algorithm: 'ed25519',
    proves: macro ? MACRO_PROVES : GATE_PROVES,
    limitations: macro ? MACRO_LIMITATIONS : GATE_LIMITATIONS,
  };
}

function exactLegCheck(leg, parent, parentDigest) {
  const p = leg?.payload; const pp = parent?.payload;
  if (!isObject(p) || !isObject(pp) || pp.schema !== 'scopeblind.gate.batch/1') return 'batch leg requires a batch parent';
  if (p.batch_receipt_digest !== parentDigest) return 'batch_receipt_digest does not match the entry receipt digest';
  const matches = pp.legs.filter((x) => x?.leg_id === p.leg_id);
  if (matches.length !== 1) return `leg_id ${JSON.stringify(p.leg_id)} must appear exactly once in parent legs`;
  const expected = { ...matches[0], batch_id: pp.batch_id, decision: pp.decision, evaluated_at: pp.evaluated_at };
  for (const [k, v] of Object.entries(expected)) if (!same(p[k], v)) return `leg field ${k} does not match signed parent`;
  return null;
}

function approvalCheck(approval, parent, parentDigest) {
  const p = approval?.payload; const pp = parent?.payload;
  if (p?.evaluation_digest !== parentDigest) return 'evaluation_digest does not match the entry receipt digest';
  const expectedScope = pp?.schema === 'scopeblind.gate.batch/1' ? 'basket' : 'order';
  if (p?.scope !== expectedScope) return `approval scope must be ${expectedScope}`;
  if (pp?.decision !== 'APPROVAL_REQUIRED') return 'approval is only valid for an APPROVAL_REQUIRED parent';
  if (!same(p?.determining ?? [], pp?.determining ?? [])) return 'approval determining rules do not match parent';
  return null;
}

function fillCheck(fill, parent, legsById, legTuples) {
  const p = fill?.payload; const pp = parent?.payload;
  if (p?.batch_receipt_digest !== parent?.digest) return 'batch_receipt_digest does not match the entry receipt digest';
  const summary = legsById.get(p?.leg_id);
  const leg = legTuples.get(p?.leg_id);
  if (!summary || !leg) return `leg_id ${JSON.stringify(p?.leg_id)} is not represented by exactly one signed leg`;
  for (const k of ['symbol', 'side']) if (p[k] !== summary[k]) return `fill field ${k} does not match signed leg`;
  if (p.qty_ordered !== summary.qty) return 'fill qty_ordered does not match signed leg qty';
  if (p.schema === 'scopeblind.gate.fill/2') {
    if (p.batch_id !== pp.batch_id) return 'fill batch_id does not match parent';
    if (p.leg_receipt_digest !== leg.digest) return 'leg_receipt_digest does not match signed leg';
    if (p.source?.verification_key?.toLowerCase() !== fill.verification_key?.toLowerCase()) return 'fill source key does not match fill signer';
  }
  return null;
}

function orderStateCheck(state, parent, legsById, legTuples, fillsByDigest) {
  const p = state?.payload; const summary = legsById.get(p?.leg_id); const leg = legTuples.get(p?.leg_id); const fill = fillsByDigest.get(p?.fill_receipt_digest);
  if (!summary || !leg || !fill) return 'order state cannot resolve its leg and fill';
  if (p.batch_receipt_digest !== parent.digest || p.leg_receipt_digest !== leg.digest) return 'order state parent digest mismatch';
  if (fill.payload.status !== 'partial' || p.remaining_qty !== fill.payload.remaining_qty || p.client_order_id !== fill.payload.client_order_id) return 'order state does not exactly match the partial fill';
  return null;
}

function manifestShape(entries) {
  return entries.map((e) => ({
    receipt_digest: e.receipt?.digest,
    leg_digests: (e.legs || []).map((x) => x?.digest),
    approval_digest: e.approval?.digest ?? null,
    fill_digests: (e.fills || []).map((x) => x?.digest),
    order_state_digests: (e.order_states || []).map((x) => x?.digest),
  }));
}

export function verifyGateBundle(bundle, opts = {}) {
  const results = { valid: true, format: 'gate-evidence-bundle', schema: bundle?.schema, exportedAt: bundle?.exported_at, gateVerificationKey: isString(bundle?.gate_verification_key) ? bundle.gate_verification_key : null, entryCount: 0, total: 0, passed: 0, failed: 0, cryptoFailed: 0, chainChecks: 0, chainFailed: 0, errors: [], records: [], signers: [], entriesUseGateKey: true, manifestValid: null, proves: GATE_BUNDLE_PROVES, limitations: GATE_LIMITATIONS };
  if (!isObject(bundle) || !Array.isArray(bundle.entries) || !['scopeblind.gate.evidence-bundle/1', GATE_BUNDLE_SCHEMA].includes(bundle.schema)) return { ...results, valid: false, error: 'unknown_format', detail: 'unsupported bundle schema or missing entries array' };
  results.entryCount = bundle.entries.length;
  if (!HEX_64.test(results.gateVerificationKey || '')) return { ...results, valid: false, error: 'no_public_key', detail: 'bundle requires gate_verification_key' };
  const gateKey = results.gateVerificationKey.toLowerCase();
  if (isString(opts.publicKey) && opts.publicKey.toLowerCase() !== gateKey) return { ...results, valid: false, error: 'key_mismatch', detail: 'bundle gate_verification_key does not match --key' };
  const signerRoles = new Map(); let firstError = null;
  const add = (tuple, role, entry, chainError = null, pinGate = false) => {
    results.total++;
    const r = verifyGateTuple(tuple, pinGate ? { publicKey: gateKey } : {});
    const key = isString(tuple?.verification_key) ? tuple.verification_key.toLowerCase() : null;
    if (key) { if (!signerRoles.has(key)) signerRoles.set(key, new Set()); signerRoles.get(key).add(role); }
    const record = { entry: entry + 1, role, id: tuple?.payload?.leg_id ?? tuple?.payload?.subject ?? tuple?.payload?.proposal_id ?? tuple?.payload?.batch_id, schema: r.schema, schemaRecognized: r.schemaRecognized, cryptoValid: r.valid, cryptoError: r.valid ? undefined : r.error, chainValid: chainError === null ? null : false, chainDetail: chainError || undefined, signer: tuple?.verification_key, digest: tuple?.digest };
    results.records.push(record);
    if (!r.valid) { results.cryptoFailed++; results.valid = false; firstError ||= r.error; results.errors.push(`[crypto] Entry ${entry + 1} ${role}: ${r.error}${r.detail ? ` (${r.detail})` : ''}`); }
    if (chainError !== null) { results.chainChecks++; results.chainFailed++; results.valid = false; results.errors.push(`[chain] Entry ${entry + 1} ${role}: ${chainError}`); }
    else if (role !== 'receipt' && role !== 'manifest' && role !== 'delegation') results.chainChecks++;
    if (r.valid && chainError === null) results.passed++; else results.failed++;
    return r;
  };

  if (bundle.schema === GATE_BUNDLE_SCHEMA) {
    const mr = add(bundle.manifest, 'manifest', -1, null, true);
    results.manifestValid = mr.valid;
    if (mr.valid) {
      const p = bundle.manifest.payload;
      const expected = manifestShape(bundle.entries);
      const recordCount = expected.reduce((n, e) => n + 1 + e.leg_digests.length + (e.approval_digest ? 1 : 0) + e.fill_digests.length + e.order_state_digests.length, 0);
      const historyHead = bytesToHex(sha256(utf8ToBytes(canonicalGateJSON(bundle.entries.map((e) => e?.receipt?.digest)))));
      const manifestError = p.gate_verification_key !== gateKey ? 'manifest gate key mismatch'
        : p.exported_at !== bundle.exported_at ? 'manifest export time mismatch'
        : !same(p.entries, expected) ? 'manifest digest inventory does not exactly match bundle entries'
        : p.record_count !== recordCount ? 'manifest record_count mismatch'
        : p.completeness?.history_entry_count !== bundle.entries.length ? 'manifest completeness count mismatch'
        : p.history_head_digest !== historyHead ? 'manifest history_head_digest mismatch'
        : null;
      if (manifestError) { results.valid = false; results.manifestValid = false; results.chainChecks++; results.chainFailed++; results.errors.push(`[chain] Manifest: ${manifestError}`); }
      else results.chainChecks++;
    }
  } else {
    results.manifestValid = false;
    results.valid = false;
    results.chainChecks++; results.chainFailed++;
    results.errors.push('[chain] Legacy bundle has no signed completeness manifest; export evidence-bundle/2');
  }

  for (let i = 0; i < bundle.entries.length; i++) {
    const e = bundle.entries[i] || {}; const parent = e.receipt;
    add(parent, 'receipt', i, null, true);
    if (parent?.verification_key?.toLowerCase() !== gateKey) results.entriesUseGateKey = false;
    const summaries = Array.isArray(parent?.payload?.legs) ? parent.payload.legs : [];
    const legsById = new Map(summaries.map((x) => [x.leg_id, x]));
    const legTuples = new Map();
    for (const leg of Array.isArray(e.legs) ? e.legs : []) {
      const err = exactLegCheck(leg, parent, parent?.digest);
      add(leg, 'leg', i, err, true);
      if (!legTuples.has(leg?.payload?.leg_id)) legTuples.set(leg?.payload?.leg_id, leg);
      else { results.valid = false; results.chainFailed++; results.errors.push(`[chain] Entry ${i + 1} duplicate signed leg ${leg?.payload?.leg_id}`); }
    }
    if (parent?.payload?.schema === 'scopeblind.gate.batch/1' && (e.legs || []).length !== summaries.length) { results.valid = false; results.chainChecks++; results.chainFailed++; results.errors.push(`[chain] Entry ${i + 1} signed leg count does not match parent`); }
    if (e.approval) add(e.approval, 'approval', i, approvalCheck(e.approval, parent, parent?.digest), false);
    // Execution evidence requires a RELEASED decision. An ALLOW parent is
    // released by definition; an APPROVAL_REQUIRED parent is released only by
    // a present approval whose decision is "approved" (its own crypto and
    // chain validity are checked above). Fills under a DENY, REVIEW, held, or
    // declined parent are evidence of an unauthorized execution and fail the
    // bundle even when every signature is individually valid.
    const fillsPresent = Array.isArray(e.fills) && e.fills.length > 0;
    if (fillsPresent) {
      const decision = parent?.payload?.decision;
      const released = decision === 'ALLOW'
        || (decision === 'APPROVAL_REQUIRED' && e.approval?.payload?.decision === 'approved');
      results.chainChecks++;
      if (!released) {
        results.valid = false;
        results.chainFailed++;
        const why = decision === 'APPROVAL_REQUIRED'
          ? (e.approval ? `approval decision is ${JSON.stringify(e.approval?.payload?.decision)}` : 'no approval is present')
          : `parent decision is ${JSON.stringify(decision)}`;
        results.errors.push(`[chain] Entry ${i + 1}: fills present but the decision was never released (${why})`);
      }
    }
    const fillsByDigest = new Map();
    for (const fill of Array.isArray(e.fills) ? e.fills : []) { const err = fillCheck(fill, parent, legsById, legTuples); add(fill, 'fill', i, err, false); fillsByDigest.set(fill?.digest, fill); }
    const statesByFill = new Map();
    for (const state of Array.isArray(e.order_states) ? e.order_states : []) {
      add(state, 'order_state', i, orderStateCheck(state, parent, legsById, legTuples, fillsByDigest), true);
      statesByFill.set(state?.payload?.fill_receipt_digest, state);
    }
    for (const fill of Array.isArray(e.fills) ? e.fills : []) {
      if (fill?.payload?.status === 'partial' && !statesByFill.has(fill.digest)) {
        results.valid = false;
        results.chainChecks++;
        results.chainFailed++;
        results.errors.push(`[chain] Entry ${i + 1} partial fill ${fill?.payload?.fill_id ?? fill?.digest} has no gate-signed held-remainder state`);
      }
    }
    const delegation = parent?.payload?.mandate?.delegation;
    if (delegation) {
      const p = delegation.payload;
      const err = p?.child_mandate_digest !== parent.payload.mandate_digest ? 'delegation child digest does not match decision mandate'
        : p?.parent_mandate_digest !== parent.payload.mandate?.parent_digest ? 'delegation parent digest does not match decision lineage'
        : p?.holder_verification_key?.toLowerCase() !== parent.verification_key?.toLowerCase() ? 'delegation holder key does not match decision signer'
        : p?.issuer_verification_key?.toLowerCase() !== delegation.verification_key?.toLowerCase() ? 'delegation issuer key mismatch'
        : Date.parse(p?.expires_at) <= Date.parse(parent.payload.evaluated_at) ? 'delegation expired before decision'
        : null;
      add(delegation, 'delegation', i, err, false);
    }
  }
  results.signers = [...signerRoles.entries()].map(([key, roles]) => ({ key, roles: [...roles].sort(), isGateKey: key === gateKey }));
  if (!results.valid) results.error = firstError || 'chain_link_mismatch';
  return results;
}
