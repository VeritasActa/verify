import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { detectFormat } from '../../src/detect.js';
import { verifyLegateStandard } from '../../src/engines/legate-standard.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = (name) => join(here, '..', 'fixtures', 'legate', name);
const fixture = (name) => JSON.parse(readFileSync(fixturePath(name), 'utf8'));
const NOW = new Date('2026-09-12T00:00:00Z');

test('a run manifest is detected and verifies alone as intact but unbound', async () => {
  const manifest = fixture('run-manifest.json');
  assert.equal(detectFormat(manifest).mode, 'legate-standard');
  const r = await verifyLegateStandard(manifest, { now: NOW });
  assert.equal(r.valid, true, JSON.stringify(r.checks));
  assert.equal(r.artifact_type, 'scopeblind.run_manifest.v1');
  assert.equal(r.binding, 'manifest_only');
  assert.equal(r.summary.passed, 1);
  assert.equal(r.signer.demo, true);
  assert.match(r.in_plain_words, /Result: 1 of 1 passed; 3 governed calls, 1 refused/);
  assert.ok(r.not_established.some((s) => /supply the signed standard/.test(s)));
});

test('with the standard and the receipts beside it, the run manifest is bound and every check passes', async () => {
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts: fixture('run-receipts.json') });
  assert.equal(r.valid, true);
  assert.equal(r.binding, 'bound', JSON.stringify(r.checks.filter((c) => !c.ok)));
  assert.equal(r.chain.count, 3);
  assert.equal(r.chain.deny, 1);
  assert.ok(r.checks.some((c) => c.id === 'tools' && c.ok));
  assert.ok(r.checks.some((c) => c.id === 'chain_head' && c.ok));
  assert.ok(r.establishes.some((s) => /every allowed call on the tool list/.test(s)));
});

test('a manifest whose score was raised fails on its digest', async () => {
  const manifest = fixture('run-manifest.json');
  manifest.summary.passed += 1;
  const r = await verifyLegateStandard(manifest, { now: NOW });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'digest_mismatch');
});

test('a receipt log with a receipt removed does not bind to the manifest', async () => {
  const receipts = fixture('run-receipts.json').slice(0, -1);
  const r = await verifyLegateStandard(fixture('run-manifest.json'), { now: NOW, standard: fixture('run-standard.json'), receipts });
  assert.equal(r.valid, true);
  assert.notEqual(r.binding, 'bound');
  assert.ok(r.checks.some((c) => c.id === 'chain_head' && !c.ok));
});

test('the CLI takes --standard and --receipts and reports the binding', () => {
  const cli = join(here, '..', '..', 'cli.js');
  const r = spawnSync(process.execPath, [cli, fixturePath('run-manifest.json'), '--standard', fixturePath('run-standard.json'), '--receipts', fixturePath('run-receipts.json'), '--json'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout);
  assert.equal(out.valid, true);
  assert.equal(out.binding, 'bound');
  const alone = spawnSync(process.execPath, [cli, fixturePath('run-manifest.json')], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
  assert.equal(alone.status, 0, alone.stderr);
  assert.match(alone.stdout, /Run manifest verifies: 1 of 1 passed, unbound/);
  assert.match(alone.stdout, /manifest only \(add --standard and --receipts to bind\)/);
});
