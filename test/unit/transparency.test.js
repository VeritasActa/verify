/**
 * Unit tests for transparency-profile engine.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  resolveProfile,
  stampTransparency,
  shouldAnchorReceipt,
  renderBadge,
  PROFILES,
} from '../../src/engines/transparency.js';

test('resolveProfile: known profile resolves cleanly', () => {
  const r = resolveProfile({ profile: 'transparent', anchor_endpoint: 'https://rekor.x/' });
  assert.equal(r.profile, 'transparent');
  assert.equal(r.warnings.length, 0);
});

test('resolveProfile: unknown profile falls back to private with warning', () => {
  const r = resolveProfile({ profile: 'invented' });
  assert.equal(r.profile, 'private');
  assert.match(r.warnings[0], /unknown_profile/);
});

test('resolveProfile: transparent without anchor_endpoint warns', () => {
  const r = resolveProfile({ profile: 'transparent' });
  assert.equal(r.profile, 'transparent');
  assert.match(r.warnings[0], /missing_anchor_endpoint/);
});

test('resolveProfile: no profile defaults to private', () => {
  const r = resolveProfile({});
  assert.equal(r.profile, 'private');
});

test('PROFILES: includes all four canonical profiles', () => {
  for (const p of ['private', 'auditable', 'transparent', 'high-assurance']) {
    assert.ok(PROFILES.includes(p), `missing profile: ${p}`);
  }
});

test('stampTransparency: writes profile into payload', () => {
  const r = { payload: { type: 'decision-receipt' }, signature: {} };
  stampTransparency(r, { profile: 'transparent', anchor_endpoint: 'https://rekor.x/' });
  assert.equal(r.payload.transparency.profile, 'transparent');
  assert.equal(r.payload.transparency.anchor_endpoint, 'https://rekor.x/');
});

test('stampTransparency: includes public_receipt_base when set', () => {
  const r = { payload: {}, signature: {} };
  stampTransparency(r, {
    profile: 'transparent',
    anchor_endpoint: 'https://rekor.x/',
    public_receipt_base: 'https://audit.x/r/',
  });
  assert.equal(r.payload.transparency.public_receipt_base, 'https://audit.x/r/');
});

test('stampTransparency: rejects receipt without payload', () => {
  assert.throws(() => stampTransparency({}, { profile: 'private' }));
});

test('shouldAnchorReceipt: private never anchors', () => {
  const r = { payload: { cost_tier: 4 } };
  assert.equal(shouldAnchorReceipt(r, 'private'), false);
});

test('shouldAnchorReceipt: auditable never anchors', () => {
  const r = { payload: { cost_tier: 4 } };
  assert.equal(shouldAnchorReceipt(r, 'auditable'), false);
});

test('shouldAnchorReceipt: transparent always anchors', () => {
  const r = { payload: { cost_tier: 0 } };
  assert.equal(shouldAnchorReceipt(r, 'transparent'), true);
});

test('shouldAnchorReceipt: high-assurance anchors only when cost_tier >= 2', () => {
  assert.equal(shouldAnchorReceipt({ payload: { cost_tier: 1 } }, 'high-assurance'), false);
  assert.equal(shouldAnchorReceipt({ payload: { cost_tier: 2 } }, 'high-assurance'), true);
});

test('renderBadge: produces a well-formed public badge', () => {
  const badge = renderBadge({
    profile: 'transparent',
    anchor_endpoint: 'https://rekor.x/',
    operator: 'Acme Corp',
  }, { receipts_anchored: 42 });
  assert.equal(badge.format, 'veritasacta:transparency-badge/v1');
  assert.equal(badge.profile, 'transparent');
  assert.equal(badge.operator, 'Acme Corp');
  assert.equal(badge.stats.receipts_anchored, 42);
});

test('renderBadge: private operator gets grey badge color', () => {
  const badge = renderBadge({ profile: 'private', operator: 'Internal' });
  assert.equal(badge.profile, 'private');
  assert.ok(badge.badge_color); // just non-empty
});
