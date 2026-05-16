/**
 * Unit tests for receipt-watcher rule evaluation + webhook formatting.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { evaluateRules, formatWebhookPayload } from '../../src/engines/watch.js';

// ───── Rule evaluation ─────

test('evaluateRules: cost_tier_below fires when below threshold', () => {
  const r = { payload: { action: 'Bash', cost_tier: 0 } };
  const fired = evaluateRules(r, [
    { id: 'r1', kind: 'cost_tier_below', params: { threshold: 2 } },
  ]);
  assert.equal(fired.length, 1);
  assert.equal(fired[0].rule_id, 'r1');
});

test('evaluateRules: cost_tier_below silent when at/above threshold', () => {
  const r = { payload: { action: 'Bash', cost_tier: 3 } };
  const fired = evaluateRules(r, [
    { id: 'r1', kind: 'cost_tier_below', params: { threshold: 2 } },
  ]);
  assert.equal(fired.length, 0);
});

test('evaluateRules: cost_tier_below treats missing cost_tier as T0', () => {
  const r = { payload: { action: 'Read' } };
  const fired = evaluateRules(r, [
    { id: 'r1', kind: 'cost_tier_below', params: { threshold: 1 } },
  ]);
  assert.equal(fired.length, 1);
});

test('evaluateRules: delegation_expiring_within fires for near-expiry', () => {
  const soonMs = Date.now() + 60_000; // 60s out
  const r = {
    payload: {
      type: 'delegation',
      delegate_kid: 'bot',
      expires_at: new Date(soonMs).toISOString(),
    },
  };
  const fired = evaluateRules(r, [
    { id: 'r2', kind: 'delegation_expiring_within', params: { within_sec: 300 } },
  ]);
  assert.equal(fired.length, 1);
  assert.match(fired[0].message, /expires in/);
});

test('evaluateRules: delegation_expiring_within silent for already-expired', () => {
  const r = {
    payload: {
      type: 'delegation',
      expires_at: '2020-01-01T00:00:00Z',  // long expired
    },
  };
  const fired = evaluateRules(r, [
    { id: 'r2', kind: 'delegation_expiring_within', params: { within_sec: 300 } },
  ]);
  // The rule fires for UPCOMING expiry; expired-already is a separate concern.
  assert.equal(fired.length, 0);
});

test('evaluateRules: deny_decision fires on deny', () => {
  const r = { payload: { action: 'Bash', decision: 'deny' } };
  const fired = evaluateRules(r, [
    { id: 'r3', kind: 'deny_decision', params: {} },
  ]);
  assert.equal(fired.length, 1);
  assert.match(fired[0].message, /deny decision/);
});

test('evaluateRules: scrub_triggered fires when scrub_detected is non-empty', () => {
  const r = {
    payload: {
      action: 'apiCall',
      scrub_detected: ['headers.authorization', 'body.api_key'],
    },
  };
  const fired = evaluateRules(r, [
    { id: 'r4', kind: 'scrub_triggered', params: {} },
  ]);
  assert.equal(fired.length, 1);
  assert.match(fired[0].message, /redacted 2 field/);
});

test('evaluateRules: multiple rules can fire in parallel', () => {
  const r = {
    payload: {
      action: 'Bash',
      cost_tier: 0,
      decision: 'deny',
    },
  };
  const fired = evaluateRules(r, [
    { id: 'r1', kind: 'cost_tier_below', params: { threshold: 1 } },
    { id: 'r3', kind: 'deny_decision', params: {} },
  ]);
  assert.equal(fired.length, 2);
});

test('evaluateRules: unknown rule kind is silently skipped', () => {
  const r = { payload: {} };
  const fired = evaluateRules(r, [
    { id: 'rX', kind: 'invented', params: {} },
  ]);
  assert.equal(fired.length, 0);
});

// ───── Webhook formatting ─────

test('formatWebhookPayload: generic produces flat JSON', () => {
  const fired = { rule_id: 'r1', kind: 'cost_tier_below', message: 'tier 0 < 2' };
  const r = {
    payload: { action: 'Bash', issued_at: '2026-04-20T00:00:00Z' },
    signature: { kid: 'agent-1' },
  };
  const p = formatWebhookPayload(fired, r, 'generic');
  assert.equal(p.rule_id, 'r1');
  assert.equal(p.receipt_action, 'Bash');
  assert.equal(p.receipt_kid, 'agent-1');
});

test('formatWebhookPayload: slack produces blocks structure', () => {
  const fired = { rule_id: 'r1', kind: 'deny_decision', message: 'denied' };
  const r = { payload: {}, signature: { kid: 'x' } };
  const p = formatWebhookPayload(fired, r, 'slack');
  assert.match(p.text, /Veritas Acta alert/);
  assert.equal(p.blocks[0].type, 'section');
});

test('formatWebhookPayload: discord uses content + embeds', () => {
  const fired = { rule_id: 'r1', kind: 'deny_decision', message: 'denied' };
  const r = { payload: {}, signature: { kid: 'x' } };
  const p = formatWebhookPayload(fired, r, 'discord');
  assert.match(p.content, /Veritas Acta/);
  assert.equal(p.embeds[0].title, 'r1');
});
