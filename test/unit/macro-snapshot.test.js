/**
 * Unit tests for the ScopeBlind macro-engine snapshot and track-record
 * verifier. Mirrors the conventions in gate-receipt.test.js: tuples are
 * signed with the SAME wire contract (digest = sha256 of canonical JSON of
 * the payload; signature = Ed25519 over the bytes of the hex digest).
 *
 * @module test/unit/macro-snapshot.test
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes, bytesToHex } from '@noble/hashes/utils';
import { detectFormat } from '../../src/detect.js';
import { verifyGateTuple } from '../../src/engines/gate-receipt.js';
import {
  macroSchemaErrors,
  macroSummary,
  isMacroSchema,
  verifyMacroTrackRecord,
  verifyInclusion,
  verifyTransparencyEvidence,
  MACRO_SCHEMAS,
} from '../../src/engines/macro-snapshot.js';
import { exitCodeFor } from '../../src/errors.js';

function deepSort(o) { if (o === null || typeof o !== 'object') return o; if (Array.isArray(o)) return o.map(deepSort); return Object.fromEntries(Object.keys(o).sort().map((k) => [k, deepSort(o[k])])); }
function h2b(hex) { return Uint8Array.from({ length: hex.length / 2 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16)); }
function mkSigner() { const priv = new Uint8Array(randomBytes(32)); return { priv, vk: bytesToHex(ed25519.getPublicKey(priv)) }; }
function signTuple(payload, signer) { const digest = bytesToHex(sha256(utf8ToBytes(JSON.stringify(deepSort(payload))))); return { payload, digest, signature: bytesToHex(ed25519.sign(h2b(digest), signer.priv)), verification_key: signer.vk }; }
const HEX = (c) => c.repeat(64);

// ── Payload fixtures ─────────────────────────────────────────────────

const marketStatePayload = (o = {}) => ({
  schema: 'scopeblind.macro.market-state/1', engine_version: 'macro-engine/0.1.0', as_of: '2025-08-23',
  universe_digest: HEX('e'), inputs_digest: HEX('7'),
  pillars: { trend: -2, breadth: 0, liquidity: -2, credit: -2, volatility: -2 },
  evidence: { trend: { inputs: [], missing: [] } }, classification: 'stress', confidence: 0.8,
  would_change: ['robust'], notes: ['n'], ...o,
});
const regimePayload = (o = {}) => ({
  schema: 'scopeblind.macro.regime-snapshot/1', engine_version: 'macro-engine/0.1.0', as_of: '2026-05-01',
  pillars: { growth: -2, inflation: 2, liquidity: -2, policy_freedom: -2, credit_conditions: -2 },
  inputs: [{ series_id: 'ICSA', z: -6.7, vote: -2 }], vintage_digest: HEX('7'),
  candidate_regime: 'stagflation', regime: 'stagflation', liquidity_overlay: 'contraction',
  hysteresis: { current: 'stagflation' }, playbook: { prefer: ['gold'] }, confidence: 0.95,
  would_change: ['robust'], notes: ['n'], ...o,
});
const tapePayload = (o = {}) => ({
  schema: 'scopeblind.macro.tape-snapshot/1', engine_version: 'macro-engine/0.1.0', as_of: '2025-08-23',
  session: 'daily_close', tape_type: 'mixed', coherence: 0, material: true,
  signals: [{ id: 'credit', z: -4 }], unavailable: ['oil'], untestable_types: ['inflation_shock'],
  attribution: { tier: 'unknown', detail: 'd', events: [] }, inputs_digest: HEX('c'),
  would_change: ['x'], notes: ['n'], ...o,
});
const vulnerabilityPayload = (o = {}) => ({
  schema: 'scopeblind.macro.vulnerability/1', engine_version: 'macro-engine/0.1.0', as_of: '2025-08-23',
  posture: { regime: 'stagflation', market_state: 'stress', refs: [] },
  factor_exposures: [{ factor: 'equity_beta', net: 0.55 }],
  betas: [{ factor: 'equity_beta', beta: 0.56 }],
  vulnerabilities: [{ factor: 'equity_beta', pain: 1.1 }, { factor: 'credit', pain: 0.3 }],
  inputs_digest: HEX('a'), would_change: ['x'], notes: ['n'], ...o,
});
const alertPayload = (o = {}) => ({
  schema: 'scopeblind.macro.alert/1', engine_version: 'macro-engine/0.1.0', as_of: '2025-08-23',
  alert_id: HEX('a'),
  kind: 'market_state_change', severity: 'critical', title: 'mixed -> stress', detail: 'd',
  refs: [{ schema: 'scopeblind.macro.market-state/1', as_of: '2025-08-23', digest: HEX('d') }],
  budget: { position: 1, max_per_day: 2 }, ...o,
});
const journalPayload = (o = {}) => ({
  schema: 'scopeblind.macro.journal-entry/1', engine_version: 'macro-engine/0.1.0', as_of: '2025-08-23',
  author: 'demo-model', note: 'note',
  references: [{ schema: 'scopeblind.macro.market-state/1', as_of: '2025-08-23', digest: HEX('d') }],
  tags: ['risk-off'], ...o,
});
const priceSnapshotPayload = (o = {}) => ({
  schema: 'scopeblind.macro.price-snapshot/1', engine_version: 'macro-engine/0.1.0',
  as_of: '2026-06-12T20:00:00Z', source: 'demo feed (delayed)', delay_minutes: 15,
  levels: {
    equity: { level: 741.75, instrument: 'SPY', unit: 'price', multiplier: 500 },
    rates: { level: 85.77, instrument: 'TLT', unit: 'price' },
  },
  coverage: ['equity', 'rates'], missing: [], notes: [], ...o,
});
const transparencyHeadPayload = (o = {}) => ({
  schema: 'scopeblind.macro.transparency-head/1', engine_version: 'macro-engine/0.1.0',
  log_id: 'scopeblind.macro.demo-log', tree_size: 6, root_hash: HEX('1'),
  timestamp: '2026-05-01T00:00:00Z', previous_root_hash: null, ...o,
});
const transparencyWitnessPayload = (o = {}) => ({
  schema: 'scopeblind.macro.transparency-witness/1', engine_version: 'macro-engine/0.1.0',
  head_digest: HEX('4'), root_hash: HEX('1'), tree_size: 6,
  witnessed_at: '2026-05-01T00:00:00Z', note: 'witness', ...o,
});

const SCHEMA_FIXTURES = [
  ['market-state', marketStatePayload],
  ['regime-snapshot', regimePayload],
  ['tape-snapshot', tapePayload],
  ['vulnerability', vulnerabilityPayload],
  ['alert', alertPayload],
  ['journal-entry', journalPayload],
  ['price-snapshot', priceSnapshotPayload],
  ['transparency-head', transparencyHeadPayload],
  ['transparency-witness', transparencyWitnessPayload],
];

// ── Recognition + semantic validation ────────────────────────────────

test('isMacroSchema recognizes the macro prefix only', () => {
  assert.equal(isMacroSchema('scopeblind.macro.market-state/1'), true);
  assert.equal(isMacroSchema('scopeblind.gate.decision/2'), false);
  assert.equal(isMacroSchema(undefined), false);
});

for (const [name, mk] of SCHEMA_FIXTURES) {
  test(`${name}: recognized, semantically valid, and cryptographically verifiable`, () => {
    const r = verifyGateTuple(signTuple(mk(), mkSigner()));
    assert.equal(r.valid, true);
    assert.equal(r.schemaRecognized, true);
    assert.equal(r.macroSchema, true);
    assert.equal(macroSchemaErrors(mk()).length, 0);
    assert.ok(r.macroSummary, 'expected a macroSummary');
    assert.equal(r.macroSummary.schema, mk().schema);
    assert.ok(Object.hasOwn(MACRO_SCHEMAS, mk().schema));
  });
}

test('market-state: invalid classification and out-of-range pillar/confidence are rejected', () => {
  assert.ok(macroSchemaErrors(marketStatePayload({ classification: 'euphoria' })).some((e) => e.includes('classification')));
  assert.ok(macroSchemaErrors(marketStatePayload({ pillars: { trend: 3, breadth: 0, liquidity: 0, credit: 0, volatility: 0 } })).some((e) => e.includes('pillar trend')));
  assert.ok(macroSchemaErrors(marketStatePayload({ confidence: 1.5 })).some((e) => e.includes('confidence')));
});

test('regime: invalid regime and non-hex vintage_digest are rejected', () => {
  assert.ok(macroSchemaErrors(regimePayload({ regime: 'boom' })).some((e) => e.includes('invalid regime')));
  assert.ok(macroSchemaErrors(regimePayload({ vintage_digest: 'short' })).some((e) => e.includes('vintage_digest')));
});

test('tape: invalid tape_type and out-of-range coherence are rejected', () => {
  assert.ok(macroSchemaErrors(tapePayload({ tape_type: 'meltup' })).some((e) => e.includes('tape_type')));
  assert.ok(macroSchemaErrors(tapePayload({ coherence: 2 })).some((e) => e.includes('coherence')));
});

test('alert: invalid severity/kind and bad refs are rejected', () => {
  assert.ok(macroSchemaErrors(alertPayload({ severity: 'meh' })).some((e) => e.includes('severity')));
  assert.ok(macroSchemaErrors(alertPayload({ kind: 'nope' })).some((e) => e.includes('kind')));
  assert.ok(macroSchemaErrors(alertPayload({ refs: [] })).some((e) => e.includes('refs')));
  assert.ok(macroSchemaErrors(alertPayload({ refs: [{ schema: 'x', as_of: 'y', digest: 'short' }] })).some((e) => e.includes('refs')));
});

test('journal entry with zero references is invalid', () => {
  const errs = macroSchemaErrors(journalPayload({ references: [] }));
  assert.ok(errs.some((e) => e.includes('references')));
});

test('price-snapshot: bad unit, negative delay, and overstated coverage are rejected', () => {
  assert.ok(macroSchemaErrors(priceSnapshotPayload({ levels: { equity: { level: 1, instrument: 'SPY', unit: 'lots' } }, coverage: ['equity'] })).some((e) => e.includes('invalid unit')));
  assert.ok(macroSchemaErrors(priceSnapshotPayload({ delay_minutes: -1 })).some((e) => e.includes('delay_minutes')));
  assert.ok(macroSchemaErrors(priceSnapshotPayload({ coverage: ['equity', 'rates', 'fx_eur'] })).some((e) => e.includes('coverage must list exactly')));
  assert.ok(macroSchemaErrors(priceSnapshotPayload({ levels: { equity: { level: 1, instrument: 'SPY', unit: 'price', multiplier: -5 } }, coverage: ['equity'] })).some((e) => e.includes('multiplier')));
  assert.equal(macroSchemaErrors(priceSnapshotPayload()).length, 0);
});

test('price-snapshot summary reports source, delay, and priced/missing counts', () => {
  const s = macroSummary(priceSnapshotPayload());
  assert.equal(s.schema, 'scopeblind.macro.price-snapshot/1');
  assert.equal(s.priced, 2);
  assert.equal(s.missing, 0);
  assert.equal(s.delay_minutes, 15);
});

test('a missing required field is reported as a schema error', () => {
  const { schema, ...rest } = marketStatePayload();
  delete rest.classification;
  const errs = macroSchemaErrors({ schema, ...rest });
  assert.ok(errs.some((e) => e.includes('missing classification')));
});

test('signed but semantically invalid macro tuple fails schema validation (exit 1)', () => {
  const r = verifyGateTuple(signTuple(alertPayload({ severity: 'bogus' }), mkSigner()));
  assert.equal(r.valid, false);
  assert.equal(r.error, 'schema_invalid');
  assert.equal(r.macroSchema, true);
  assert.equal(exitCodeFor('schema_invalid'), 1);
});

test('tampered macro payload fails digest verification', () => {
  const t = signTuple(marketStatePayload(), mkSigner());
  t.payload.classification = 'risk_on';
  assert.equal(verifyGateTuple(t).error, 'digest_mismatch');
});

test('an unknown macro schema is not semantically constrained but stays a macro tuple', () => {
  const t = signTuple({ schema: 'scopeblind.macro.future/9', as_of: '2025-08-23', x: 1 }, mkSigner());
  const r = verifyGateTuple(t);
  assert.equal(r.valid, true);
  assert.equal(r.macroSchema, true);
  // not in MACRO_SCHEMAS, so no semantic contract and no summary
  assert.equal(macroSchemaErrors(t.payload).length, 0);
  assert.equal(macroSummary(t.payload), null);
});

test('macroSummary surfaces the salient fields per schema', () => {
  assert.equal(macroSummary(marketStatePayload()).classification, 'stress');
  assert.equal(macroSummary(regimePayload()).regime, 'stagflation');
  assert.equal(macroSummary(tapePayload()).tape_type, 'mixed');
  assert.equal(macroSummary(tapePayload()).attribution_tier, 'unknown');
  assert.equal(macroSummary(vulnerabilityPayload()).top_vulnerabilities[0].factor, 'equity_beta');
  assert.equal(macroSummary(alertPayload()).severity, 'critical');
  assert.equal(macroSummary(journalPayload()).reference_count, 1);
  assert.equal(macroSummary({ schema: 'scopeblind.gate.decision/2' }), null);
});

// ── Track-record bundle ──────────────────────────────────────────────

function buildValidBundle({ signer = mkSigner() } = {}) {
  const snapshots = [
    signTuple(marketStatePayload(), signer),
    signTuple(tapePayload(), signer),
    signTuple(regimePayload(), signer),
    signTuple(vulnerabilityPayload(), signer),
    signTuple(alertPayload(), signer),
  ];
  const journal = [signTuple(journalPayload(), signer)];
  const ordered = [...snapshots, ...journal];
  const exported_at = '2026-05-01T00:00:00Z';
  const period = { from: '2025-01-02', to: '2026-05-01' };
  const entries = ordered.map((t) => ({ schema: t.payload.schema, as_of: t.payload.as_of, digest: t.digest }));
  const history_head_digest = bytesToHex(sha256(utf8ToBytes(JSON.stringify(deepSort(ordered.map((t) => t.digest))))));
  const manifestPayload = {
    schema: 'scopeblind.macro.track-record-manifest/1', engine_version: 'macro-engine/0.1.0',
    exported_at, model_verification_key: signer.vk, period, entries,
    snapshot_count: snapshots.length, journal_count: journal.length, history_head_digest,
  };
  const bundle = {
    schema: 'scopeblind.macro.track-record-bundle/1', version: '0.1.0', exported_at,
    model_verification_key: signer.vk, custody: 'dev-deterministic', period,
    snapshots, journal, manifest: signTuple(manifestPayload, signer),
  };
  return { bundle, signer };
}

// Resign the manifest after mutating the bundle's record set, so that the
// failure under test is the inventory/count/history check rather than a stale
// manifest signature.
function resignManifest(bundle, signer, patch = {}) {
  const ordered = [...bundle.snapshots, ...bundle.journal];
  const entries = ordered.map((t) => ({ schema: t.payload.schema, as_of: t.payload.as_of, digest: t.digest }));
  const history_head_digest = bytesToHex(sha256(utf8ToBytes(JSON.stringify(deepSort(ordered.map((t) => t.digest))))));
  const payload = {
    ...bundle.manifest.payload, entries,
    snapshot_count: bundle.snapshots.length, journal_count: bundle.journal.length,
    history_head_digest, ...patch,
  };
  bundle.manifest = signTuple(payload, signer);
}

test('detectFormat: macro track-record bundle', () => {
  const { bundle } = buildValidBundle();
  const r = detectFormat(bundle);
  assert.equal(r.mode, 'macro-track-record');
  assert.equal(r.isBundle, true);
});

test('valid track-record bundle verifies all records, custody, manifest, and history head', () => {
  const { bundle, signer } = buildValidBundle();
  const r = verifyMacroTrackRecord(bundle, { publicKey: signer.vk });
  assert.equal(r.valid, true);
  assert.equal(r.total, 7);
  assert.equal(r.passed, 7);
  assert.equal(r.snapshotCount, 5);
  assert.equal(r.journalCount, 1);
  assert.equal(r.manifestValid, true);
  assert.equal(r.singleSigner, true);
  assert.equal(r.chainFailed, 0);
  assert.equal(r.signerPinned, true);
  assert.equal(r.identityStatus, 'pinned_operator_key');
});

test('without --key a valid bundle proves integrity but not operator identity', () => {
  const { bundle } = buildValidBundle();
  const r = verifyMacroTrackRecord(bundle);
  assert.equal(r.valid, true);
  assert.equal(r.signerPinned, false);
  assert.equal(r.identityStatus, 'embedded_key_only');
});

test('bundle --key mismatch fails before trusting the embedded model key', () => {
  const { bundle } = buildValidBundle();
  const r = verifyMacroTrackRecord(bundle, { publicKey: mkSigner().vk });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'key_mismatch');
});

test('dropping a snapshot from the bundle fails (manifest inventory + count)', () => {
  const { bundle, signer } = buildValidBundle();
  bundle.snapshots.pop();
  // manifest still enumerates the dropped record → mismatch detected
  const r = verifyMacroTrackRecord(bundle, { publicKey: signer.vk });
  assert.equal(r.valid, false);
  assert.equal(r.manifestValid, false);
  assert.ok(r.errors.some((e) => e.includes('Manifest')));
});

test('a coherently re-exported smaller bundle (record dropped + manifest resigned) verifies', () => {
  // The exporter signs what it retained at export time; a smaller set whose
  // manifest inventory, counts, and history head all match is internally
  // consistent and verifies. (Dropping a record WITHOUT resigning fails, per
  // the prior test.)
  const { bundle, signer } = buildValidBundle();
  bundle.snapshots.pop();
  resignManifest(bundle, signer);
  const r = verifyMacroTrackRecord(bundle, { publicKey: signer.vk });
  assert.equal(r.valid, true);
  assert.equal(r.snapshotCount, 4);
});

test('anchored append-only exports verify previous-head links and independent head pins', () => {
  const { bundle: first, signer } = buildValidBundle();
  first.manifest = signTuple({
    ...first.manifest.payload,
    sequence: 1,
    previous_manifest_digest: null,
    previous_history_head_digest: null,
  }, signer);
  const anchor1 = signTuple({
    schema: 'scopeblind.macro.track-record-anchor/1',
    engine_version: 'macro-engine/0.1.0',
    anchored_at: first.exported_at,
    sequence: 1,
    manifest_digest: first.manifest.digest,
    history_head_digest: first.manifest.payload.history_head_digest,
    previous_anchor_digest: null,
  }, signer);
  first.prior_manifests = [];
  first.anchor_chain = [anchor1];

  const second = structuredClone(first);
  second.exported_at = '2026-05-08T00:00:00Z';
  second.prior_manifests = [first.manifest];
  const secondPayload = {
    ...second.manifest.payload,
    exported_at: second.exported_at,
    sequence: 2,
    previous_manifest_digest: first.manifest.digest,
    previous_history_head_digest: first.manifest.payload.history_head_digest,
  };
  second.manifest = signTuple(secondPayload, signer);
  const anchor2 = signTuple({
    schema: 'scopeblind.macro.track-record-anchor/1',
    engine_version: 'macro-engine/0.1.0',
    anchored_at: second.exported_at,
    sequence: 2,
    manifest_digest: second.manifest.digest,
    history_head_digest: second.manifest.payload.history_head_digest,
    previous_anchor_digest: anchor1.digest,
  }, signer);
  second.anchor_chain = [anchor1, anchor2];

  const r = verifyMacroTrackRecord(second, {
    publicKey: signer.vk,
    historyHead: second.manifest.payload.history_head_digest,
    anchorHead: anchor2.digest,
  });
  assert.equal(r.valid, true, JSON.stringify(r.errors));
  assert.equal(r.historyChainValid, true);
  assert.equal(r.historyAnchored, true);
  assert.equal(r.historyHeadPinned, true);
  assert.equal(r.anchorHeadPinned, true);
  assert.equal(r.sequence, 2);

  const erased = structuredClone(second);
  erased.snapshots.shift();
  resignManifest(erased, signer, {
    sequence: 2,
    previous_manifest_digest: first.manifest.digest,
    previous_history_head_digest: first.manifest.payload.history_head_digest,
  });
  erased.anchor_chain = [];
  const erasedResult = verifyMacroTrackRecord(erased, { publicKey: signer.vk });
  assert.equal(erasedResult.valid, false);
  assert.ok(erasedResult.errors.some((error) => error.includes('omits prior record')));
});

test('tampering a record payload fails the bundle (digest mismatch)', () => {
  const { bundle, signer } = buildValidBundle();
  bundle.snapshots[0].payload.classification = 'risk_on';
  const r = verifyMacroTrackRecord(bundle, { publicKey: signer.vk });
  assert.equal(r.valid, false);
  assert.ok(r.cryptoFailed >= 1);
  assert.ok(r.errors.some((e) => e.includes('[crypto]')));
});

test('a foreign-signer record fails the single-signer custody check', () => {
  const { bundle, signer } = buildValidBundle();
  const foreigner = mkSigner();
  // Re-sign the first snapshot with a different key, keep manifest entry (same
  // schema/as_of/digest) so the inventory still matches; only custody differs.
  bundle.snapshots[0] = signTuple(bundle.snapshots[0].payload, foreigner);
  resignManifest(bundle, signer);
  const r = verifyMacroTrackRecord(bundle, { publicKey: signer.vk });
  assert.equal(r.valid, false);
  assert.equal(r.singleSigner, false);
  assert.ok(r.errors.some((e) => e.includes('single-signer custody')));
});

test('manifest signature tamper is a crypto failure', () => {
  const { bundle, signer } = buildValidBundle();
  bundle.manifest.payload.snapshot_count = 999;
  const r = verifyMacroTrackRecord(bundle, { publicKey: signer.vk });
  assert.equal(r.valid, false);
  assert.ok(r.cryptoFailed >= 1);
  assert.equal(r.manifestValid, false);
});

test('history_head_digest tamper is detected', () => {
  const { bundle, signer } = buildValidBundle();
  bundle.manifest = signTuple({ ...bundle.manifest.payload, history_head_digest: HEX('0') }, signer);
  const r = verifyMacroTrackRecord(bundle, { publicKey: signer.vk });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes('history_head_digest')));
});

test('reordering records so the manifest inventory no longer matches in-order fails', () => {
  const { bundle, signer } = buildValidBundle();
  // swap two snapshots without resigning the manifest: in-order inventory now mismatches
  [bundle.snapshots[0], bundle.snapshots[1]] = [bundle.snapshots[1], bundle.snapshots[0]];
  const r = verifyMacroTrackRecord(bundle, { publicKey: signer.vk });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => e.includes('Manifest')));
});

test('non-bundle input is rejected as unknown_format', () => {
  assert.equal(verifyMacroTrackRecord({ schema: 'x' }).error, 'unknown_format');
  assert.equal(verifyMacroTrackRecord(null).error, 'unknown_format');
});

test('missing model_verification_key is undecidable', () => {
  const { bundle } = buildValidBundle();
  delete bundle.model_verification_key;
  assert.equal(verifyMacroTrackRecord(bundle).error, 'no_public_key');
});

// ── RFC 6962 transparency log ─────────────────────────────────────────

const SAMPLE_BUNDLE = JSON.parse(readFileSync(
  fileURLToPath(new URL('../../samples/macro/track-record-bundle.json', import.meta.url)),
  'utf-8',
));

test('transparency-head: invalid tree_size, root_hash, and previous_root_hash are rejected', () => {
  assert.ok(macroSchemaErrors(transparencyHeadPayload({ tree_size: -1 })).some((e) => e.includes('tree_size')));
  assert.ok(macroSchemaErrors(transparencyHeadPayload({ root_hash: 'short' })).some((e) => e.includes('root_hash')));
  assert.ok(macroSchemaErrors(transparencyHeadPayload({ previous_root_hash: 'short' })).some((e) => e.includes('previous_root_hash')));
  // null genesis previous_root_hash is valid; a missing key is not.
  assert.equal(macroSchemaErrors(transparencyHeadPayload({ previous_root_hash: null })).length, 0);
  const { previous_root_hash, ...noPrev } = transparencyHeadPayload();
  assert.ok(macroSchemaErrors(noPrev).some((e) => e.includes('previous_root_hash')));
});

test('transparency-witness: invalid head_digest, root_hash, and tree_size are rejected', () => {
  assert.ok(macroSchemaErrors(transparencyWitnessPayload({ head_digest: 'short' })).some((e) => e.includes('head_digest')));
  assert.ok(macroSchemaErrors(transparencyWitnessPayload({ root_hash: 'short' })).some((e) => e.includes('root_hash')));
  assert.ok(macroSchemaErrors(transparencyWitnessPayload({ tree_size: 'six' })).some((e) => e.includes('tree_size')));
});

test('tampering a transparency head fails digest verification', () => {
  const t = signTuple(transparencyHeadPayload(), mkSigner());
  t.payload.tree_size = 7;
  assert.equal(verifyGateTuple(t).error, 'digest_mismatch');
});

test('macroSummary surfaces transparency head/witness salient fields', () => {
  const h = macroSummary(transparencyHeadPayload());
  assert.equal(h.log_id, 'scopeblind.macro.demo-log');
  assert.equal(h.tree_size, 6);
  assert.equal(h.root_hash, HEX('1'));
  const w = macroSummary(transparencyWitnessPayload());
  assert.equal(w.head_digest, HEX('4'));
  assert.equal(w.tree_size, 6);
});

test('verifyInclusion: every sample proof verifies against the signed head root', () => {
  const root = SAMPLE_BUNDLE.transparency.head.payload.root_hash;
  for (const inc of SAMPLE_BUNDLE.transparency.inclusions) {
    assert.equal(verifyInclusion(inc.digest, inc.proof, root), true, `leaf ${inc.proof.leaf_index}`);
  }
});

test('verifyInclusion: a flipped path node, wrong digest, or wrong root all fail', () => {
  const root = SAMPLE_BUNDLE.transparency.head.payload.root_hash;
  const inc = SAMPLE_BUNDLE.transparency.inclusions[0];
  const flipped = { ...inc.proof, audit_path: inc.proof.audit_path.slice() };
  flipped.audit_path[0] = (flipped.audit_path[0][0] === 'f' ? '0' : 'f') + flipped.audit_path[0].slice(1);
  assert.equal(verifyInclusion(inc.digest, flipped, root), false, 'flipped path node');
  assert.equal(verifyInclusion(HEX('a'), inc.proof, root), false, 'wrong digest');
  assert.equal(verifyInclusion(inc.digest, inc.proof, HEX('b')), false, 'wrong root');
});

test('verifyInclusion: out-of-range leaf_index is rejected', () => {
  const root = SAMPLE_BUNDLE.transparency.head.payload.root_hash;
  const inc = SAMPLE_BUNDLE.transparency.inclusions[0];
  assert.equal(verifyInclusion(inc.digest, { ...inc.proof, leaf_index: 6 }, root), false);
  assert.equal(verifyInclusion(inc.digest, { ...inc.proof, leaf_index: -1 }, root), false);
});

test('verifyTransparencyEvidence: sample bundle is witnessed and all included', () => {
  const recordDigests = [...SAMPLE_BUNDLE.snapshots, ...SAMPLE_BUNDLE.journal].map((t) => t.digest);
  const r = verifyTransparencyEvidence(SAMPLE_BUNDLE.transparency, recordDigests);
  assert.equal(r.head_valid, true);
  assert.equal(r.all_included, true);
  assert.equal(r.witness_present, true);
  assert.equal(r.witness_independent, true);
  assert.equal(r.anchor, 'witnessed');
  // The Merkle log has exactly one leaf per record (snapshots + journal); assert
  // that invariant rather than a magic count, so a change in bundle composition
  // (e.g. a state-change alert present or absent in the demo world) does not
  // falsely fail a verifier test that is really about inclusion + witnessing.
  assert.equal(r.tree_size, recordDigests.length);
  assert.equal(r.errors.length, 0);
});

test('verifyTransparencyEvidence: a record outside the checked set is not affected, but a checked record missing an inclusion fails', () => {
  const recordDigests = [...SAMPLE_BUNDLE.snapshots, ...SAMPLE_BUNDLE.journal].map((t) => t.digest);
  // Adding a record that has no inclusion proof => all_included false.
  const r = verifyTransparencyEvidence(SAMPLE_BUNDLE.transparency, [...recordDigests, HEX('e')]);
  assert.equal(r.head_valid, true);
  assert.equal(r.all_included, false);
  assert.equal(r.anchor, 'none');
  assert.ok(r.errors.some((e) => e.includes('not provably included')));
});

test('verifyTransparencyEvidence: without an independent witness the anchor is self_signed', () => {
  const recordDigests = [...SAMPLE_BUNDLE.snapshots, ...SAMPLE_BUNDLE.journal].map((t) => t.digest);
  const noWitness = { head: SAMPLE_BUNDLE.transparency.head, inclusions: SAMPLE_BUNDLE.transparency.inclusions };
  const r = verifyTransparencyEvidence(noWitness, recordDigests);
  assert.equal(r.head_valid, true);
  assert.equal(r.all_included, true);
  assert.equal(r.witness_present, false);
  assert.equal(r.witness_independent, false);
  assert.equal(r.anchor, 'self_signed');
});

test('verifyTransparencyEvidence: a head signed by the model key (not independent) is self_signed', () => {
  const recordDigests = [...SAMPLE_BUNDLE.snapshots, ...SAMPLE_BUNDLE.journal].map((t) => t.digest);
  // Witness re-signed by the same key as the head => present but not independent.
  const sameKeyWitness = {
    head: SAMPLE_BUNDLE.transparency.head,
    witness: { ...SAMPLE_BUNDLE.transparency.witness, verification_key: SAMPLE_BUNDLE.transparency.head.verification_key },
    inclusions: SAMPLE_BUNDLE.transparency.inclusions,
  };
  const r = verifyTransparencyEvidence(sameKeyWitness, recordDigests);
  // The witness signature no longer verifies under the model key, so it is not
  // counted as a co-signature; the anchor falls back to self_signed.
  assert.equal(r.head_valid, true);
  assert.equal(r.all_included, true);
  assert.equal(r.witness_independent, false);
  assert.equal(r.anchor, 'self_signed');
});

test('verifyMacroTrackRecord: the sample bundle is witness-anchored and valid', () => {
  const r = verifyMacroTrackRecord(SAMPLE_BUNDLE);
  assert.equal(r.valid, true);
  assert.ok(r.transparencyAnchor, 'expected a transparencyAnchor');
  assert.equal(r.transparencyAnchor.anchor, 'witnessed');
  assert.equal(r.transparencyAnchor.all_included, true);
});

test('verifyMacroTrackRecord: a bundle without transparency stays valid (backward compatible)', () => {
  const { bundle, signer } = buildValidBundle();
  const r = verifyMacroTrackRecord(bundle, { publicKey: signer.vk });
  assert.equal(r.valid, true);
  assert.equal(r.transparencyAnchor, null);
});

test('verifyMacroTrackRecord: a tampered transparency root fails the bundle with a [chain] error', () => {
  const tampered = structuredClone(SAMPLE_BUNDLE);
  // Break the head root so no inclusion can verify against it (and head schema
  // semantics still hold; the failure is inclusion, surfaced as head/include).
  tampered.transparency.inclusions[0].proof.audit_path[0] = HEX('0');
  const r = verifyMacroTrackRecord(tampered);
  assert.equal(r.valid, false);
  assert.equal(r.transparencyAnchor.all_included, false);
  assert.ok(r.errors.some((e) => e.includes('[chain] Transparency')));
});
