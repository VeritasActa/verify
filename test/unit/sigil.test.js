/**
 * Unit tests for Sigil claim 1 (derivation / self-check) and claim 2
 * (live-context verification).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  deriveSigilHash,
  deriveSigilGrid,
  sigilPassesFilter,
  deriveFilteredSigil,
  selfCheck,
  evaluateLiveContext,
} from '../../src/engines/sigil.js';
import { parseContextArgs } from '../../src/context/live-context.js';

test('deriveSigilHash: deterministic', () => {
  const pubkey = 'a'.repeat(64);
  const policyHash = 'b'.repeat(64);
  const h1 = deriveSigilHash(pubkey, policyHash, 0);
  const h2 = deriveSigilHash(pubkey, policyHash, 0);
  assert.equal(h1, h2);
  assert.equal(h1.length, 64);
});

test('deriveSigilHash: nonce changes output', () => {
  const pubkey = 'a'.repeat(64);
  const policyHash = 'b'.repeat(64);
  assert.notEqual(deriveSigilHash(pubkey, policyHash, 0), deriveSigilHash(pubkey, policyHash, 1));
});

test('deriveFilteredSigil: produces filter-passing grid', () => {
  const { grid, fingerprint } = deriveFilteredSigil('0'.repeat(64));
  assert.ok(sigilPassesFilter(grid), 'grid should pass filter');
  assert.equal(fingerprint.length, 8);
});

test('sigilPassesFilter: rejects all-zero grid', () => {
  const zeroGrid = {
    diamond: { top: 0, right: 0, bottom: 0, left: 0 },
    surround: [0, 0, 0, 0],
    innerRing: [0, 0, 0, 0, 0, 0],
    midRing: [0, 0, 0, 0, 0, 0],
    outerRing: [0, 0, 0, 0, 0, 0],
    corners: [0, 0, 0, 0, 0, 0, 0, 0],
  };
  assert.equal(sigilPassesFilter(zeroGrid), false);
});

test('selfCheck: canonical match', () => {
  // Build a tiny "installed" byte set and a matching sigil.json
  const installedSourceBytes = Buffer.from('module.exports = {};');
  const sourceHash = createHash('sha256').update(installedSourceBytes).digest('hex');
  const policy = {
    version: 3,
    package: '@veritasacta/verify',
    package_version: '0.5.0',
    source_hash: sourceHash,
    ietf_draft: 'draft-farley-acta-signed-receipts-03',
    created_at: 0,
  };
  const policyHash = createHash('sha256').update(JSON.stringify(policy)).digest('hex');
  const projectPubKey = '0'.repeat(64);
  const sigilHash = deriveSigilHash(projectPubKey, policyHash, 0);
  const sigil = {
    sigil_version: 1,
    fingerprint: sigilHash.slice(0, 8),
    name: 'Test Ember',
    sigil_hash: sigilHash,
    project_public_key: projectPubKey,
    policy,
    policy_hash: policyHash,
    derived_at: '2026-04-19T00:00:00Z',
  };

  const r = selfCheck({ sigil, installedSourceBytes });
  assert.equal(r.canonical, true);
  assert.equal(r.sourceMatches, true);
  assert.equal(r.policyMatches, true);
  assert.equal(r.sigilMatches, true);
});

test('selfCheck: mismatched source detected', () => {
  const installedSourceBytes = Buffer.from('different bytes');
  const policy = {
    source_hash: 'a'.repeat(64),
    package: '@veritasacta/verify',
    package_version: '0.5.0',
  };
  const sigil = {
    policy,
    policy_hash: 'b'.repeat(64),
    project_public_key: '0'.repeat(64),
    sigil_hash: 'c'.repeat(64),
  };
  const r = selfCheck({ sigil, installedSourceBytes });
  assert.equal(r.canonical, false);
  assert.equal(r.sourceMatches, false);
});

test('parseContextArgs: parses clock predicate', () => {
  const p = parseContextArgs(['clock:±5s']);
  assert.equal(p.length, 1);
  assert.equal(p[0].kind, 'clock');
  assert.equal(p[0].expr, '±5s');
});

test('parseContextArgs: parses sensor predicate', () => {
  const p = parseContextArgs(['sensor:temp<18']);
  assert.equal(p[0].kind, 'sensor');
  assert.equal(p[0].expr, 'temp<18');
});

test('evaluateLiveContext: sensor predicate with supplied value', async () => {
  const preds = [{ kind: 'sensor', expr: 'temp<18', options: { value: 15 } }];
  const r = await evaluateLiveContext(preds);
  assert.equal(r.allSatisfied, true);
  assert.equal(r.checks[0].satisfied, true);
});

test('evaluateLiveContext: sensor predicate fails when value exceeds bound', async () => {
  const preds = [{ kind: 'sensor', expr: 'temp<18', options: { value: 22.4 } }];
  const r = await evaluateLiveContext(preds);
  assert.equal(r.allSatisfied, false);
  assert.equal(r.checks[0].satisfied, false);
});
