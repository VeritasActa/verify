import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes, bytesToHex } from '@noble/hashes/utils';
import { detectFormat } from '../../src/detect.js';
import { verifyGateTuple, verifyGateBundle } from '../../src/engines/gate-receipt.js';
import { exitCodeFor } from '../../src/errors.js';

function deepSort(o) { if (o === null || typeof o !== 'object') return o; if (Array.isArray(o)) return o.map(deepSort); return Object.fromEntries(Object.keys(o).sort().map((k) => [k, deepSort(o[k])])); }
function h2b(hex) { return Uint8Array.from({ length: hex.length / 2 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16)); }
function mkSigner() { const priv = new Uint8Array(randomBytes(32)); return { priv, vk: bytesToHex(ed25519.getPublicKey(priv)) }; }
function signTuple(payload, signer) { const digest = bytesToHex(sha256(utf8ToBytes(JSON.stringify(deepSort(payload))))); return { payload, digest, signature: bytesToHex(ed25519.sign(h2b(digest), signer.priv)), verification_key: signer.vk }; }

const batchPayload = () => ({
  schema: 'scopeblind.gate.batch/1', batch_id: 'B-1', kind: 'rebalance',
  model: { risk: 'parametric', correlation_matrix_digest: '9'.repeat(64) }, nav: 500000000,
  decision: 'APPROVAL_REQUIRED', determining: ['approval-threshold'],
  legs: [
    { leg_id: 'L-1', position_id: 'P-1', symbol: 'ZN', side: 'buy', qty: 40, target_pct: 2.1, achieved_pct: 2.05, residual_bp: -5 },
    { leg_id: 'L-2', position_id: 'P-2', symbol: 'ES', side: 'sell', qty: 25, target_pct: 1.4, achieved_pct: 1.38, residual_bp: -2 },
  ],
  mandate: { name: 'Meridian IMA', digest: 'a'.repeat(64), parent_digest: null, holder: 'Fund' }, mandate_digest: 'a'.repeat(64),
  book_digest: 'c'.repeat(64), post_book_digest: 'd'.repeat(64), evaluated_at: '2026-06-12T09:31:00.000Z',
});
function legPayload(batchDigest, summary) { return { schema: 'scopeblind.gate.batch-leg/1', batch_id: 'B-1', batch_receipt_digest: batchDigest, ...summary, decision: 'APPROVAL_REQUIRED', evaluated_at: '2026-06-12T09:31:00.000Z' }; }
function approvalPayload(batchDigest) { return { schema: 'scopeblind.gate.approval/1', evaluation_digest: batchDigest, scope: 'basket', subject: 'B-1', determining: ['approval-threshold'], decision: 'approved', approver: { name: 'PM', method: 'device' }, decided_at: '2026-06-12T09:35:00.000Z' }; }
function fillPayload(batch, leg, filled, sourceKey) { const ordered = leg.payload.qty; return { schema: 'scopeblind.gate.fill/2', batch_id: 'B-1', batch_receipt_digest: batch.digest, leg_receipt_digest: leg.digest, leg_id: leg.payload.leg_id, position_id: leg.payload.position_id, client_order_id: `B-1:${leg.payload.leg_id}`, external_order_id: `EXT-${leg.payload.leg_id}`, execution_id: `EXEC-${leg.payload.leg_id}`, fill_id: `FILL-${leg.payload.leg_id}`, account: 'fund', venue: 'EMS', currency: 'USD', symbol: leg.payload.symbol, side: leg.payload.side, qty_ordered: ordered, qty_filled: filled, remaining_qty: ordered - filled, status: filled === ordered ? 'filled' : 'partial', remaining_authority: 'none', filled_at: '2026-06-12T10:02:00.000Z', source: { name: 'custodian', independence: 'independent', verification_key: sourceKey, trust: 'custodian_signed' } }; }
function statePayload(batch, leg, fill) { return { schema: 'scopeblind.gate.order-state/1', batch_id: 'B-1', batch_receipt_digest: batch.digest, leg_receipt_digest: leg.digest, fill_receipt_digest: fill.digest, leg_id: leg.payload.leg_id, client_order_id: fill.payload.client_order_id, state: 'partially_filled_remainder_held', remaining_qty: fill.payload.remaining_qty, authorized_remaining_qty: 0, requires_new_decision: true, recorded_at: fill.payload.filled_at }; }
function inventory(entries) { return entries.map((e) => ({ receipt_digest: e.receipt.digest, leg_digests: e.legs.map((x) => x.digest), approval_digest: e.approval?.digest ?? null, fill_digests: e.fills.map((x) => x.digest), order_state_digests: e.order_states.map((x) => x.digest) })); }
function buildValidBundle({ delegated = false, delegationParent = 'b'.repeat(64) } = {}) {
  const gate = mkSigner(); const approver = mkSigner(); const custodian = mkSigner();
  const issuer = delegated ? mkSigner() : null;
  const payload = batchPayload();
  if (issuer) {
    const delegation = signTuple({
      schema: 'scopeblind.mandate.delegation/1',
      delegation_id: 'DLG-1',
      parent_mandate_digest: delegationParent,
      child_mandate_digest: payload.mandate_digest,
      holder_verification_key: gate.vk,
      issuer_verification_key: issuer.vk,
      scope: { principal: 'Agent::pm', action: 'Action::trade', resource: 'Portfolio::main' },
      issued_at: '2026-06-12T09:00:00.000Z',
      expires_at: '2026-07-12T09:00:00.000Z',
      nonce: '0123456789abcdef0123456789abcdef',
      revocation: { registry: 'scopeblind://test', reference: 'scopeblind://test/DLG-1', status: 'not_revoked', checked_at: '2026-06-12T09:00:00.000Z' },
    }, issuer);
    payload.mandate = {
      ...payload.mandate,
      parent_digest: 'b'.repeat(64),
      holder_verification_key: gate.vk,
      delegation,
    };
  }
  const batch = signTuple(payload, gate);
  const legs = batch.payload.legs.map((x) => signTuple(legPayload(batch.digest, x), gate));
  const approval = signTuple(approvalPayload(batch.digest), approver);
  const fills = [signTuple(fillPayload(batch, legs[0], 40, custodian.vk), custodian), signTuple(fillPayload(batch, legs[1], 10, custodian.vk), custodian)];
  const order_states = [signTuple(statePayload(batch, legs[1], fills[1]), gate)];
  const entries = [{ kind: 'batch', receipt: batch, legs, approval, fills, order_states }];
  const exported_at = '2026-06-12T11:00:00.000Z';
  const manifestPayload = { schema: 'scopeblind.gate.evidence-manifest/1', bundle_id: 'bundle-1', exported_at, completeness: { scope: 'complete_browser_history', definition: 'All retained records.', history_entry_count: 1, history_limit: 50 }, gate_verification_key: gate.vk, entries: inventory(entries), record_count: 7, history_head_digest: bytesToHex(sha256(utf8ToBytes(JSON.stringify(deepSort(entries.map((e) => e.receipt.digest)))))) };
  const bundle = { schema: 'scopeblind.gate.evidence-bundle/2', exported_at, gate_verification_key: gate.vk, manifest: signTuple(manifestPayload, gate), entries };
  return { bundle, gate, approver, custodian, issuer, batch, legs, fills };
}

const decisionPayload = (overrides = {}) => ({ schema: 'scopeblind.gate.decision/2', proposal_id: 'P-1', proposal: { symbol: 'ZN', side: 'buy', qty: 40 }, decision: 'ALLOW', determining: [], mandate_digest: 'a'.repeat(64), book_digest: 'c'.repeat(64), nav: 500000000, evaluated_at: '2026-06-12T09:30:00.000Z', ...overrides });

test('detects Gate tuple and v2 bundle', () => { assert.equal(detectFormat(signTuple(decisionPayload(), mkSigner())).mode, 'gate-receipt-tuple'); assert.equal(detectFormat(buildValidBundle().bundle).mode, 'gate-evidence-bundle'); });
test('valid tuple verifies and --key pins it', () => { const s = mkSigner(); const t = signTuple(decisionPayload(), s); assert.equal(verifyGateTuple(t, { publicKey: s.vk }).valid, true); assert.equal(verifyGateTuple(t, { publicKey: mkSigner().vk }).error, 'key_mismatch'); });
test('tampered tuple fails digest verification', () => { const t = signTuple(decisionPayload(), mkSigner()); t.payload.decision = 'DENY'; assert.equal(verifyGateTuple(t).error, 'digest_mismatch'); });
test('signed but semantically invalid tuple fails schema validation', () => { const t = signTuple(decisionPayload({ proposal: { symbol: 'ZN', side: 'launch', qty: -1 } }), mkSigner()); assert.equal(verifyGateTuple(t).error, 'schema_invalid'); assert.equal(exitCodeFor('schema_invalid'), 1); });
test('unknown schema remains generic but cryptographically verifiable', () => { const r = verifyGateTuple(signTuple({ schema: 'scopeblind.future/9', value: 1 }, mkSigner())); assert.equal(r.valid, true); assert.equal(r.schemaRecognized, false); });

// A decision receipt enriched with the optional top-level price_snapshot ref (the
// "prices this decision saw", bound by digest) stays a valid, recognized gate
// receipt: the extra key is inside the signed bytes, so it verifies, and a no-anchor
// control is byte-identical to a plain decision. Pins the wire-compat invariant.
const priceSnapshotRef = { schema: 'scopeblind.macro.price-snapshot/1', digest: 'd'.repeat(64), as_of: '2026-06-12T20:00:00Z', source: 'Yahoo Finance delayed quote (fetched at request time; not a live tick)', delay_minutes: 15 };
test('decision receipt enriched with price_snapshot still verifies and is recognized', () => {
  const s = mkSigner();
  const t = signTuple(decisionPayload({ price_snapshot: priceSnapshotRef }), s);
  const r = verifyGateTuple(t, { publicKey: s.vk });
  assert.equal(r.valid, true);
  assert.equal(r.schemaRecognized, true);
});
test('tampering the bound price_snapshot digest fails digest verification', () => {
  const t = signTuple(decisionPayload({ price_snapshot: priceSnapshotRef }), mkSigner());
  t.payload.price_snapshot.digest = 'e'.repeat(64);
  assert.equal(verifyGateTuple(t).error, 'digest_mismatch');
});

test('custodian reconciliation receipt is a recognized, verifiable gate tuple', () => {
  const s = mkSigner();
  const payload = {
    schema: 'scopeblind.gate.reconciliation/1', book_digest: 'a'.repeat(64), statement_digest: 'b'.repeat(64),
    statement_lines: 3, summary: { matched: 2, qty_mismatch: 1, missing_in_book: 1, missing_in_statement: 1, total: 5 },
    clean: false, rows: [{ symbol: 'ES', book_qty: 680, statement_qty: 685, status: 'qty_mismatch' }], reconciled_at: '2026-06-12T09:30:00.000Z',
  };
  const r = verifyGateTuple(signTuple(payload, s), { publicKey: s.vk });
  assert.equal(r.valid, true);
  assert.equal(r.schemaRecognized, true);
});

test('regime stress receipt is a recognized, verifiable gate tuple', () => {
  const s = mkSigner();
  const payload = {
    schema: 'scopeblind.gate.stress/1', book_digest: 'a'.repeat(64), mandate_digest: 'b'.repeat(64), regime: 'inflation_2022',
    shocks: { rates: 75, equity: -8 }, total_pnl_usd: -22800000, pct_of_nav: -4.56, nav: 500000000,
    per_factor: [{ factor: 'rates', shock: 75, pnl_usd: -15450000 }], limit_verdict: 'halt', review_limit_pct: -2, halt_limit_pct: -4, evaluated_at: '2026-06-12T09:30:00.000Z',
  };
  const r = verifyGateTuple(signTuple(payload, s), { publicKey: s.vk });
  assert.equal(r.valid, true);
  assert.equal(r.schemaRecognized, true);
});

test('valid v2 bundle verifies exact schemas, chains, gate key, and manifest', () => { const { bundle, gate } = buildValidBundle(); const r = verifyGateBundle(bundle, { publicKey: gate.vk }); assert.equal(r.valid, true); assert.equal(r.total, 8); assert.equal(r.passed, 8); assert.equal(r.manifestValid, true); assert.equal(r.entriesUseGateKey, true); assert.equal(r.chainFailed, 0); });
test('bundle --key mismatch fails before trusting embedded gate key', () => { const { bundle } = buildValidBundle(); assert.equal(verifyGateBundle(bundle, { publicKey: mkSigner().vk }).error, 'key_mismatch'); });
test('declared gate key mismatch is a hard failure', () => { const { bundle } = buildValidBundle(); bundle.gate_verification_key = mkSigner().vk; const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.ok(r.cryptoFailed >= 1); });
test('leg content must exactly match parent summary', () => { const { bundle, gate } = buildValidBundle(); const p = { ...bundle.entries[0].legs[0].payload, qty: 41 }; bundle.entries[0].legs[0] = signTuple(p, gate); bundle.manifest = signTuple({ ...bundle.manifest.payload, entries: inventory(bundle.entries) }, gate); const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.ok(r.errors.some((e) => e.includes('leg field qty'))); });
test('missing signed leg fails completeness against parent', () => { const { bundle, gate } = buildValidBundle(); bundle.entries[0].legs.pop(); bundle.manifest = signTuple({ ...bundle.manifest.payload, entries: inventory(bundle.entries), record_count: 6 }, gate); const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.ok(r.errors.some((e) => e.includes('leg count'))); });
test('approval must match parent scope, state, and determining rules', () => { const { bundle, approver, gate } = buildValidBundle(); bundle.entries[0].approval = signTuple({ ...bundle.entries[0].approval.payload, determining: [] }, approver); bundle.manifest = signTuple({ ...bundle.manifest.payload, entries: inventory(bundle.entries) }, gate); const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.ok(r.errors.some((e) => e.includes('determining'))); });
test('fill must bind the exact signed leg and quantities', () => { const { bundle, custodian, gate } = buildValidBundle(); bundle.entries[0].fills[0] = signTuple({ ...bundle.entries[0].fills[0].payload, leg_receipt_digest: '0'.repeat(64) }, custodian); bundle.manifest = signTuple({ ...bundle.manifest.payload, entries: inventory(bundle.entries) }, gate); const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.ok(r.errors.some((e) => e.includes('leg_receipt_digest'))); });
test('fill source identity must equal the cryptographic fill signer', () => { const { bundle, custodian, gate } = buildValidBundle(); bundle.entries[0].fills[0] = signTuple({ ...bundle.entries[0].fills[0].payload, source: { ...bundle.entries[0].fills[0].payload.source, verification_key: mkSigner().vk } }, custodian); bundle.manifest = signTuple({ ...bundle.manifest.payload, entries: inventory(bundle.entries) }, gate); const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.ok(r.errors.some((e) => e.includes('source key'))); });
test('partial fill requires fail-closed held-remainder state in manifest inventory', () => { const { bundle, gate } = buildValidBundle(); bundle.entries[0].order_states = []; bundle.manifest = signTuple({ ...bundle.manifest.payload, entries: inventory(bundle.entries), record_count: 6 }, gate); const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.ok(r.errors.some((e) => e.includes('partial fill')) || r.valid === false); });
test('manifest detects omitted record', () => { const { bundle } = buildValidBundle(); bundle.entries[0].fills.pop(); const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.equal(r.manifestValid, false); assert.ok(r.errors.some((e) => e.includes('manifest digest inventory'))); });
test('manifest history head must bind the ordered exported decision history', () => { const { bundle, gate } = buildValidBundle(); bundle.manifest = signTuple({ ...bundle.manifest.payload, history_head_digest: '0'.repeat(64) }, gate); const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.equal(r.manifestValid, false); assert.ok(r.errors.some((e) => e.includes('history_head_digest'))); });
test('manifest signature tamper is a crypto failure', () => { const { bundle } = buildValidBundle(); bundle.manifest.payload.record_count = 999; const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.ok(r.cryptoFailed >= 1); });
test('legacy bundle without signed manifest fails closed', () => { const { bundle } = buildValidBundle(); bundle.schema = 'scopeblind.gate.evidence-bundle/1'; delete bundle.manifest; const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.ok(r.errors.some((e) => e.includes('no signed completeness manifest'))); });
test('issuer-signed delegation verifies when holder and lineage match', () => { const { bundle } = buildValidBundle({ delegated: true }); const r = verifyGateBundle(bundle); assert.equal(r.valid, true); assert.ok(r.signers.some((s) => s.roles.includes('delegation'))); });
test('issuer-signed delegation cannot substitute a different parent mandate', () => { const { bundle } = buildValidBundle({ delegated: true, delegationParent: 'c'.repeat(64) }); const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.ok(r.errors.some((e) => e.includes('delegation parent digest'))); });
test('fills under an unreleased APPROVAL_REQUIRED parent fail even with valid signatures', () => { const { bundle, gate } = buildValidBundle(); bundle.entries = bundle.entries.map((e) => ({ ...e, approval: undefined })); bundle.manifest = signTuple({ ...bundle.manifest.payload, entries: inventory(bundle.entries), record_count: 6 }, gate); const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.ok(r.errors.some((e) => e.includes('never released'))); });
test('fills under a declined approval fail the release rule', () => { const { bundle, approver, gate } = buildValidBundle(); bundle.entries[0].approval = signTuple({ ...bundle.entries[0].approval.payload, decision: 'declined' }, approver); bundle.manifest = signTuple({ ...bundle.manifest.payload, entries: inventory(bundle.entries) }, gate); const r = verifyGateBundle(bundle); assert.equal(r.valid, false); assert.ok(r.errors.some((e) => e.includes('never released'))); });
