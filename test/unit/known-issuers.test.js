import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadKnownIssuers, labelFor } from '../../src/util/known-issuers.js';

function fixture(obj) {
  const d = mkdtempSync(join(tmpdir(), 'ki-'));
  const p = join(d, 'k.json');
  writeFileSync(p, JSON.stringify(obj));
  return p;
}

test('loads, lowercases hex keys, and skips _comment keys', () => {
  const p = fixture({ _comment: 'doc', 'AABB': 'Meridian Global Macro Desk', 'ccdd': 'Other Desk' });
  const m = loadKnownIssuers(undefined, p);
  assert.equal(m.aabb, 'Meridian Global Macro Desk');
  assert.equal(m.ccdd, 'Other Desk');
  assert.equal(m._comment, undefined);
});

test('user file overlays the bundled defaults', () => {
  const bundled = fixture({ 'aa': 'Bundled' });
  const user = fixture({ 'aa': 'User Override', 'bb': 'User Only' });
  const m = loadKnownIssuers(user, bundled);
  assert.equal(m.aa, 'User Override');
  assert.equal(m.bb, 'User Only');
});

test('labelFor is case-insensitive and null on miss', () => {
  const m = { aabb: 'Desk' };
  assert.equal(labelFor('AABB', m), 'Desk');
  assert.equal(labelFor('ffff', m), null);
  assert.equal(labelFor(undefined, m), null);
});

test('malformed / missing files are ignored (labels are non-critical)', () => {
  assert.deepEqual(loadKnownIssuers('/no/such/file.json', undefined), {});
});
