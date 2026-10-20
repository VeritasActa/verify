import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalize } from '../../src/util/canonical.js';
import { replayChain } from '../../src/engines/bulk.js';

// Draft-03 §6.7 links the whole previous receipt, signature included, and no revision defines a link over the payload
// alone. A payload-only link is a chain break whatever the previous receipt's spec says; allowPayloadOnlyLinks reads one
// as a legacy link, counted and warned.
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
const SPEC03 = { spec: 'draft-farley-acta-signed-receipts-03' };
const SPEC02 = { spec: 'draft-farley-acta-signed-receipts-02' };

async function replay(first, secondFields, privateKey, kid, pub, opts = {}) {
  const second = receipt(privateKey, kid, secondFields);
  const dir = mkdtempSync(join(tmpdir(), 'verify-legacy-link-'));
  const file = join(dir, 'receipts.jsonl');
  writeFileSync(file, `${JSON.stringify(first)}\n${JSON.stringify(second)}\n`);
  return replayChain(file, { publicKey: pub, ...opts });
}

test('under -03 a payload-only link is a chain break', async () => {
  const { privateKey, pub } = keypair(); const kid = 'sb:issuer:test';
  const first = receipt(privateKey, kid, { ...SPEC03, decision: 'allow' });
  const r = await replay(first, { ...SPEC03, decision: 'deny', previousReceiptHash: `sha256:${sha(canonicalize(first.payload))}` }, privateKey, kid, pub);
  assert.equal(r.chainBreaks, 1);
  assert.equal(r.legacyLinks, 0);
  assert.equal(r.valid, false);
  assert.match(r.errors[0], /^Line 2: chain_break \(previousReceiptHash is the SHA-256 of line 1's payload alone/);
  assert.match(r.errors[0], /--allow-payload-only-links/);
});

test('a whole-receipt link under -03 verifies with no legacy links', async () => {
  const { privateKey, pub } = keypair(); const kid = 'sb:issuer:test';
  const first = receipt(privateKey, kid, { ...SPEC03, decision: 'allow' });
  const r = await replay(first, { ...SPEC03, decision: 'deny', previousReceiptHash: `sha256:${sha(canonicalize(first))}` }, privateKey, kid, pub);
  assert.equal(r.chainBreaks, 0);
  assert.equal(r.legacyLinks, 0);
  assert.equal(r.chains, 1);
  assert.deepEqual(r.warnings, []);
  assert.equal(r.valid, true, r.errors.join('; '));
});

test('a payload-only link is a chain break whatever the previous receipt cites, -02 and no spec included', async () => {
  const { privateKey, pub } = keypair(); const kid = 'sb:issuer:test';
  for (const [name, cites] of [['-02', SPEC02], ['no spec member', {}], ['-01', { spec: 'draft-farley-acta-signed-receipts-01' }]]) {
    const first = receipt(privateKey, kid, { ...cites, decision: 'allow' });
    for (const link of [`sha256:${sha(canonicalize(first.payload))}`, sha(canonicalize(first.payload))]) {
      const r = await replay(first, { ...SPEC03, decision: 'deny', previousReceiptHash: link }, privateKey, kid, pub);
      assert.equal(r.chainBreaks, 1, `${name} ${link.slice(0, 7)}`);
      assert.equal(r.legacyLinks, 0, name);
      assert.equal(r.valid, false, name);
      assert.match(r.errors[0], /payload alone/, name);
    }
  }
});

test('allowPayloadOnlyLinks reads a payload-only link as a legacy link, counted and warned, whatever the spec', async () => {
  const { privateKey, pub } = keypair(); const kid = 'sb:issuer:test';
  for (const cites of [SPEC03, SPEC02, {}]) {
    const first = receipt(privateKey, kid, { ...cites, decision: 'allow' });
    for (const link of [`sha256:${sha(canonicalize(first.payload))}`, sha(canonicalize(first.payload))]) {
      const r = await replay(first, { ...SPEC03, decision: 'deny', previousReceiptHash: link }, privateKey, kid, pub, { allowPayloadOnlyLinks: true });
      assert.equal(r.valid, true, r.errors.join('; '));
      assert.equal(r.chainBreaks, 0);
      assert.equal(r.legacyLinks, 1);
      assert.equal(r.warnings.length, 1);
      assert.match(r.warnings[0], /^Line 2: payload-only link to line 1, read as a legacy link because --allow-payload-only-links was given/);
    }
  }
});

test('allowPayloadOnlyLinks applies to the payload-only preimage and nothing else', async () => {
  const { privateKey, pub } = keypair(); const kid = 'sb:issuer:test';
  const first = receipt(privateKey, kid, { ...SPEC03, decision: 'allow' });
  const whole = await replay(first, { ...SPEC03, decision: 'deny', previousReceiptHash: `sha256:${sha(canonicalize(first))}` }, privateKey, kid, pub, { allowPayloadOnlyLinks: true });
  assert.equal(whole.valid, true);
  assert.equal(whole.legacyLinks, 0);
  assert.deepEqual(whole.warnings, []);
  // An unrelated digest, and the hash of the receipt with its signature member removed: a third convention, not this one.
  for (const link of [`sha256:${'ab'.repeat(32)}`, `sha256:${sha(canonicalize({ payload: first.payload }))}`]) {
    const r = await replay(first, { ...SPEC03, decision: 'deny', previousReceiptHash: link }, privateKey, kid, pub, { allowPayloadOnlyLinks: true });
    assert.equal(r.valid, false, link);
    assert.equal(r.chainBreaks, 1, link);
    assert.equal(r.legacyLinks, 0, link);
  }
});
