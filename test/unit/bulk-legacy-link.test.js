import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize } from '../../src/util/canonical.js';
import { replayChain } from '../../src/engines/bulk.js';

// Two -03 receipts, the second linked with the PAYLOAD-ONLY hash of the first: a chain break under section 6.7.
// The same log with the first receipt citing -02: the legacy link is accepted and counted.
function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  return { privateKey, pub };
}
function receipt(privateKey, kid, fields) {
  const payload = { type: 'protectmcp:decision', issued_at: '2026-09-10T00:00:00.000Z', issuer_id: kid, ...fields };
  const sig = sign(null, Buffer.from(canonicalize(payload), 'utf-8'), privateKey).toString('hex');
  return { payload, signature: { alg: 'EdDSA', kid, sig } };
}
const sha = (s) => createHash('sha256').update(s, 'utf-8').digest('hex');

async function replay(first, secondFields, privateKey, kid, pub) {
  const second = receipt(privateKey, kid, secondFields);
  const dir = mkdtempSync(join(tmpdir(), 'verify-legacy-link-'));
  const file = join(dir, 'receipts.jsonl');
  writeFileSync(file, `${JSON.stringify(first)}\n${JSON.stringify(second)}\n`);
  return replayChain(file, { publicKey: pub });
}

test('under -03 a payload-only link is a chain break', async () => {
  const { privateKey, pub } = keypair(); const kid = 'sb:issuer:test';
  const first = receipt(privateKey, kid, { spec: 'draft-farley-acta-signed-receipts-03', decision: 'allow' });
  const r = await replay(first, { spec: 'draft-farley-acta-signed-receipts-03', decision: 'deny', previousReceiptHash: `sha256:${sha(canonicalize(first.payload))}` }, privateKey, kid, pub);
  assert.equal(r.chainBreaks, 1);
  assert.equal(r.legacyLinks, 0);
  assert.equal(r.valid, false);
});

test('a whole-receipt link under -03 verifies with no legacy links', async () => {
  const { privateKey, pub } = keypair(); const kid = 'sb:issuer:test';
  const first = receipt(privateKey, kid, { spec: 'draft-farley-acta-signed-receipts-03', decision: 'allow' });
  const r = await replay(first, { spec: 'draft-farley-acta-signed-receipts-03', decision: 'deny', previousReceiptHash: `sha256:${sha(canonicalize(first))}` }, privateKey, kid, pub);
  assert.equal(r.chainBreaks, 0);
  assert.equal(r.legacyLinks, 0);
  assert.equal(r.valid, true, r.errors.join('; '));
});

test('a payload-only link after a -02 predecessor is accepted and counted as legacy', async () => {
  const { privateKey, pub } = keypair(); const kid = 'sb:issuer:test';
  const first = receipt(privateKey, kid, { spec: 'draft-farley-acta-signed-receipts-02', decision: 'allow' });
  const r = await replay(first, { spec: 'draft-farley-acta-signed-receipts-03', decision: 'deny', previousReceiptHash: `sha256:${sha(canonicalize(first.payload))}` }, privateKey, kid, pub);
  assert.equal(r.chainBreaks, 0);
  assert.equal(r.legacyLinks, 1);
  assert.equal(r.valid, true, r.errors.join('; '));
});
