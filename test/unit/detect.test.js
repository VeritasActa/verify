/**
 * Unit tests for input format detection.
 * @module test/unit/detect.test
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { detectFormat } from '../../src/detect.js';

test('detectFormat: passport envelope', () => {
  const r = detectFormat({
    payload: { type: 'scopeblind:decision', tool_name: 'x' },
    signature: { alg: 'EdDSA', kid: 'sb:abc', sig: 'aa'.repeat(64) },
  });
  assert.equal(r.mode, 'ed25519-passport');
});

test('detectFormat: v2 structured', () => {
  const r = detectFormat({
    v: 2, kid: 'x', issuer: 'i', payload: {}, signature: 'a',
  });
  assert.equal(r.mode, 'ed25519-receipt-v2');
});

test('detectFormat: v1 flat', () => {
  const r = detectFormat({ v: 1, type: 'receipt', timestamp: '2026-04-19', signature: 'a' });
  assert.equal(r.mode, 'ed25519-receipt-v1');
});

test('detectFormat: audit bundle', () => {
  const r = detectFormat({
    receipts: [{}, {}],
    verification: { signing_keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'a' }] },
  });
  assert.equal(r.mode, 'ed25519-bundle');
  assert.equal(r.isBundle, true);
});

test('detectFormat: knowledge unit', () => {
  const r = detectFormat({
    type: 'knowledge_unit',
    canonical_question: 'Q?',
    models_used: ['a'],
  });
  assert.equal(r.mode, 'knowledge-unit');
});

test('detectFormat: selective disclosure', () => {
  const r = detectFormat({
    payload: { tool_name: 'x', patient_id: 'sha256(...)' },
    signature: { alg: 'EdDSA', kid: 'k', sig: 'aa'.repeat(64) },
    _commitments: { 'payload.patient_id': 'sha256:...' },
  });
  assert.equal(r.mode, 'ed25519-passport');
  assert.equal(r.hasSelectiveDisclosure, true);
});

test('detectFormat: voprf token', () => {
  const r = detectFormat({
    token: 'aa'.repeat(33),
    proof_I: 'pi',
    scope: { origin: 'x', epoch: 1 },
  });
  assert.equal(r.mode, 'voprf-token');
});

test('detectFormat: unknown', () => {
  const r = detectFormat({ random: 'data' });
  assert.equal(r.mode, 'unknown');
});

test('detectFormat: null/non-object', () => {
  assert.equal(detectFormat(null).mode, 'unknown');
  assert.equal(detectFormat(undefined).mode, 'unknown');
  assert.equal(detectFormat([]).mode, 'unknown');
  assert.equal(detectFormat('string').mode, 'unknown');
});
