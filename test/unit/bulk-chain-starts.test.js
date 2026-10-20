/**
 * --replay-chain and a receipt after the first with no link. Draft-03 §2.2: a receipt that omits previousReceiptHash is
 * a chain genesis or an unchained receipt, and a verifier must not infer chain membership from the absence. So such a
 * receipt starts a new chain: it is counted in `chains`, named in `warnings`, and neither checked against the receipt
 * before it nor reported as a break. A null link, which the 0.9.3 proxy and daemon wrote on a first receipt, is read
 * the same way, with the receipt verifier's §2.2 warning.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../../src/util/canonical.js';
import { replayChain } from '../../src/engines/bulk.js';

const secret = new Uint8Array(32).fill(31);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const fields = (n) => ({ type: 'protectmcp:decision', spec: 'draft-farley-acta-signed-receipts-03', tool_name: `records.${n}`, decision: 'allow', issued_at: `2026-10-19T00:00:0${n}Z` });
const envelope = (payload) => ({ payload, signature: { alg: 'EdDSA', kid: 'test:chain-starts', sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), secret)) } });
const link = (r) => `sha256:${createHash('sha256').update(canonicalize(r)).digest('hex')}`;

// links[i] is the previousReceiptHash for receipt i: a function of the receipt before it, null, or undefined to omit.
function replay(links, opts = {}) {
  const receipts = [];
  links.forEach((l, i) => {
    const payload = fields(i + 1);
    const value = typeof l === 'function' ? l(receipts[i - 1]) : l;
    if (value !== undefined) payload.previousReceiptHash = value;
    receipts.push(envelope(payload));
  });
  const file = join(mkdtempSync(join(tmpdir(), 'verify-chain-starts-')), 'receipts.jsonl');
  writeFileSync(file, receipts.map((r) => JSON.stringify(r)).join('\n') + '\n');
  return replayChain(file, { publicKey, ...opts });
}

test('one chain: chains is 1 and there are no warnings', async () => {
  const r = await replay([undefined, link, link]);
  assert.equal(r.valid, true, r.errors.join('; '));
  assert.equal(r.chains, 1);
  assert.equal(r.chainBreaks, 0);
  assert.deepEqual(r.warnings, []);
});

test('a later receipt with no link starts a new chain, named and counted, not a break', async () => {
  const r = await replay([undefined, link, undefined, link]);
  assert.equal(r.valid, true, r.errors.join('; '));
  assert.equal(r.chainBreaks, 0);
  assert.equal(r.chains, 2);
  assert.deepEqual(r.warnings, ['Line 3: starts a new chain: it has no previousReceiptHash, so it is not linked to line 2 (draft §2.2).']);
});

test('the receipt after a new start is checked against that start, not against the chain before it', async () => {
  const receipts = [];
  for (let i = 0; i < 3; i++) {
    const payload = fields(i + 1);
    if (i === 1) payload.previousReceiptHash = link(receipts[0]);
    receipts.push(envelope(payload));
  }
  // Line 4 links to line 2, across the new chain that line 3 starts: a break.
  const p = fields(4); p.previousReceiptHash = link(receipts[1]); receipts.push(envelope(p));
  const file = join(mkdtempSync(join(tmpdir(), 'verify-chain-starts-')), 'receipts.jsonl');
  writeFileSync(file, receipts.map((r) => JSON.stringify(r)).join('\n') + '\n');
  const r = await replayChain(file, { publicKey });
  assert.equal(r.valid, false);
  assert.equal(r.chainBreaks, 1);
  assert.match(r.errors[0], /^Line 4: chain_break/);
  assert.equal(r.chains, 2);
});

test('a later null link starts a new chain too, with the §2.2 warning the receipt verifier gives', async () => {
  const r = await replay([undefined, link, null, link]);
  assert.equal(r.valid, true, r.errors.join('; '));
  assert.equal(r.chainBreaks, 0);
  assert.equal(r.chains, 2);
  assert.equal(r.warnings[0], 'Line 3: starts a new chain: its previousReceiptHash is null, so it is not linked to line 2 (draft §2.2).');
  assert.match(r.warnings[1], /^Line 3: previousReceiptHash is null; draft §2\.2 says the first receipt in a chain omits the member\./);
  assert.equal(r.receipts[2].warning.includes('§2.2'), true);
});

test('a null link on the first receipt is the 0.9.3 genesis form: one chain, warned', async () => {
  const r = await replay([null, link]);
  assert.equal(r.valid, true, r.errors.join('; '));
  assert.equal(r.chains, 1);
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0], /^Line 1: previousReceiptHash is null/);
});

test('a link that is not a string is a chain break and a malformed link, not a crash', async () => {
  for (const value of [7, 42, { sha256: 'ab'.repeat(32) }, ['ab'.repeat(32)], true]) {
    const r = await replay([undefined, () => value]);
    assert.equal(r.valid, false, JSON.stringify(value));
    assert.equal(r.chainBreaks, 1, JSON.stringify(value));
    assert.ok(r.errors.some((e) => e === 'Line 2: malformed_chain_link'), r.errors.join('; '));
  }
});
