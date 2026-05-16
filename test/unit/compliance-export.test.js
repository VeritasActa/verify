/**
 * Unit tests for compliance export engine.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  exportCompliance,
  renderComplianceHTML,
} from '../../src/engines/compliance-export.js';

function writeReceipt(dir, filename, payload, kid = 'test-kid') {
  const receipt = {
    payload: {
      type: 'decision-receipt',
      issuer_id: 'test-issuer',
      agent_id: 'test-agent',
      issued_at: '2026-04-15T12:00:00Z',
      ...payload,
    },
    signature: { alg: 'ed25519', kid, sig: 'deadbeef' },
  };
  writeFileSync(join(dir, filename), JSON.stringify(receipt));
}

test('exportCompliance: empty dir returns zeroed manifest', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cexp-'));
  const r = exportCompliance({ receiptsDir: dir, framework: 'soc2' });
  assert.equal(r.manifest.receipts_scanned, 0);
  assert.equal(r.manifest.receipts_in_window, 0);
  const ctrlCount = Object.keys(r.manifest.frameworks.soc2.controls).length;
  assert.ok(ctrlCount > 0);
});

test('exportCompliance: matches Write actions to SOC2 CC6.1 and CC8.1', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cexp-'));
  writeReceipt(dir, 'a.json', { action: 'Write', decision: 'allow' });
  writeReceipt(dir, 'b.json', { action: 'Read', decision: 'allow' });
  writeReceipt(dir, 'c.json', { action: 'Bash', decision: 'deny' });

  const r = exportCompliance({ receiptsDir: dir, framework: 'soc2' });
  assert.equal(r.manifest.receipts_scanned, 3);

  // CC6.1 matches Read, Write, Bash → 3 evidence
  assert.equal(r.manifest.frameworks.soc2.controls['CC6.1'].evidence_count, 3);
  // CC8.1 matches Write → 1 evidence
  assert.equal(r.manifest.frameworks.soc2.controls['CC8.1'].evidence_count, 1);
});

test('exportCompliance: date window filters receipts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cexp-'));
  writeReceipt(dir, 'before.json', { action: 'Write', issued_at: '2026-01-01T00:00:00Z' });
  writeReceipt(dir, 'in.json',     { action: 'Write', issued_at: '2026-04-15T00:00:00Z' });
  writeReceipt(dir, 'after.json',  { action: 'Write', issued_at: '2026-12-31T00:00:00Z' });

  const r = exportCompliance({
    receiptsDir: dir,
    framework: 'soc2',
    startDate: '2026-04-01T00:00:00Z',
    endDate:   '2026-05-01T00:00:00Z',
  });
  assert.equal(r.manifest.receipts_scanned, 3);
  assert.equal(r.manifest.receipts_in_window, 1);
});

test('exportCompliance: all frameworks returns three framework reports', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cexp-'));
  writeReceipt(dir, 'a.json', { action: 'Write' });
  const r = exportCompliance({ receiptsDir: dir, framework: 'all' });
  assert.ok(r.manifest.frameworks.soc2);
  assert.ok(r.manifest.frameworks.iso42001);
  assert.ok(r.manifest.frameworks['eu-ai-act']);
});

test('exportCompliance: unknown framework throws', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cexp-'));
  assert.throws(
    () => exportCompliance({ receiptsDir: dir, framework: 'gdpr-fake' }),
    /unknown_framework/
  );
});

test('exportCompliance: malformed JSON produces a warning, not a throw', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cexp-'));
  writeFileSync(join(dir, 'bad.json'), '{ not json');
  writeReceipt(dir, 'good.json', { action: 'Read' });

  const r = exportCompliance({ receiptsDir: dir, framework: 'soc2' });
  assert.equal(r.manifest.receipts_scanned, 1);
  assert.ok(r.warnings.some((w) => w.includes('bad.json')));
});

test('exportCompliance: non-receipt JSON (no payload/signature) is skipped', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cexp-'));
  writeFileSync(join(dir, 'not-a-receipt.json'), JSON.stringify({ foo: 'bar' }));
  writeReceipt(dir, 'good.json', { action: 'Read' });
  const r = exportCompliance({ receiptsDir: dir, framework: 'soc2' });
  assert.equal(r.manifest.receipts_scanned, 1);
});

test('renderComplianceHTML: produces a valid HTML document with control headers', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cexp-'));
  writeReceipt(dir, 'a.json', { action: 'Write' });
  const r = exportCompliance({
    receiptsDir: dir,
    framework: 'soc2',
    organizationName: 'Acme Corp',
  });
  const html = renderComplianceHTML(r);
  assert.match(html, /<!doctype html>/);
  assert.match(html, /Compliance Evidence Bundle/);
  assert.match(html, /Acme Corp/);
  assert.match(html, /CC6\.1/);
  assert.match(html, /CC8\.1/);
});

test('renderComplianceHTML: HTML-escapes organization name', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cexp-'));
  writeReceipt(dir, 'a.json', { action: 'Read' });
  const r = exportCompliance({
    receiptsDir: dir,
    framework: 'soc2',
    organizationName: '<script>alert(1)</script>',
  });
  const html = renderComplianceHTML(r);
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});
