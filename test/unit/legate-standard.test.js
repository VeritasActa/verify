import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { detectFormat } from '../../src/detect.js';
import { verifyLegateStandard } from '../../src/engines/legate-standard.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => JSON.parse(readFileSync(join(here, '..', 'fixtures', 'legate', name), 'utf8'));
const NOW = new Date('2026-09-10T00:00:00Z');

test('a signed standard is detected and verifies with the bundled Legate core', async () => {
  const request = fixture('proof-request.json');
  assert.equal(detectFormat(request).mode, 'legate-standard');
  const r = await verifyLegateStandard(request, { now: NOW });
  assert.equal(r.valid, true, JSON.stringify(r.checks));
  assert.equal(r.artifact_type, 'scopeblind.proof_request.v1');
  assert.equal(r.recipient.organization, 'Bank A (demo)');
  assert.match(r.in_plain_words, /Limit: each instruction at most \$250,000\.00/);
  assert.match(r.enforcement.policy_digest, /^sha256:[0-9a-f]{64}$/);
  assert.ok(r.not_established.some((s) => /Who holds the recipient key/.test(s)));
});

test('a standard whose consequence was edited after signing fails on its digest', async () => {
  const request = fixture('proof-request.json');
  request.consequence.if_met = 'Guaranteed allocation.';
  const r = await verifyLegateStandard(request, { now: NOW });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'digest_mismatch');
});

test('a recipient decision is detected and verifies, and an edited decision fails on its digest', async () => {
  const decision = fixture('admission-decision.json');
  assert.equal(detectFormat(decision).mode, 'legate-standard');
  const r = await verifyLegateStandard(decision, { now: NOW });
  assert.equal(r.valid, true, JSON.stringify(r.checks));
  assert.equal(r.artifact_type, 'scopeblind.admission_decision.v1');
  assert.equal(typeof r.bound_to.presentation_digest, 'string');
  const edited = structuredClone(decision);
  edited.decision = decision.decision === 'accept' ? 'reject' : 'accept';
  const bad = await verifyLegateStandard(edited, { now: NOW });
  assert.equal(bad.valid, false);
  assert.equal(bad.error, 'digest_mismatch');
});

test('an action assurance bundle verifies, reports unpinned signers without --key, and pins with it', async () => {
  const bundle = fixture('action-bundle.json');
  assert.equal(detectFormat(bundle).mode, 'legate-standard');
  const r = await verifyLegateStandard(bundle, { now: new Date(bundle.receipt.issued_at) });
  assert.equal(r.valid, true, JSON.stringify(r.verification));
  assert.equal(r.signers_pinned, false);
  assert.ok(r.not_established.some((s) => /nothing was pinned/.test(s)));
  const pinned = await verifyLegateStandard(bundle, { now: new Date(bundle.receipt.issued_at), publicKey: bundle.receipt.issuer.verification_key });
  assert.equal(pinned.signers_pinned, true);
});

test('evidence files are named as evidence, not verified as decisions', async () => {
  const r = await verifyLegateStandard({ type: 'scopeblind.effect_readback.v1' });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'unsupported_format');
  assert.match(r.detail, /evidence a decision was made on/);
});
