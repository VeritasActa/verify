/**
 * The terminal headline names the outcome and the check that decided it, from 0.10.26: a receipt whose signature
 * holds and whose link or key window fails is reported as INVALID for that check, with "Signature: valid" under it,
 * never as an invalid signature. Single receipts, --previous and --replay-chain alike.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../../src/util/canonical.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const secret = new Uint8Array(32).fill(61);
const other = new Uint8Array(32).fill(62);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const KID = 'test:headline';
const sha = (value) => createHash('sha256').update(canonicalize(value)).digest('hex');
const sign = (payload, key = secret) => ({ payload, signature: { alg: 'EdDSA', kid: KID, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), key)) } });
const fields = (n, extra = {}) => ({ type: 'protectmcp:decision', tool_name: `records.${n}`, decision: 'allow', spec: 'draft-farley-acta-signed-receipts-03', issued_at: `2026-03-15T00:00:0${n}Z`, ...extra });

const dir = mkdtempSync(join(tmpdir(), 'acta-headline-'));
let n = 0;
const write = (value, name = `f${n++}.json`) => { const path = join(dir, name); writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value)); return path; };
const keys = write({ keys: [{ kty: 'OKP', crv: 'Ed25519', kid: KID, x: Buffer.from(publicKey, 'hex').toString('base64url'), valid_from: '2026-01-01T00:00:00Z', valid_until: '2026-06-01T00:00:00Z' }] });
const run = (...args) => spawnSync(process.execPath, [cli, ...args, '--no-sigil'], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
const first = sign(fields(1));
const firstPath = write(first);

test('a valid receipt heads VALID, with its signature valid', () => {
  const r = run(firstPath, '--key', publicKey);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^✓ VALID: every check that applies passed$/m);
  assert.match(r.stdout, /^ {2}Signature: {2}valid$/m);
});

test('a bad signature heads INVALID for the signature, and only then says the signature is invalid', () => {
  const r = run(write(sign(fields(1), other)), '--key', publicKey);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /^✗ INVALID: the signature does not verify under the key used \(invalid_signature\)$/m);
  assert.match(r.stdout, /^ {2}Signature: {2}invalid$/m);
});

test('a key window the receipt falls outside heads INVALID for the window, with the signature valid', () => {
  const r = run(write(sign(fields(1, { issued_at: '2026-07-01T00:00:00Z' }))), '--jwks', keys);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /^✗ INVALID: key outside its validity window \(key_outside_validity_window\)$/m);
  assert.match(r.stdout, /^ {2}Signature: {2}valid$/m);
  assert.doesNotMatch(r.stdout, /Signature: +(INVALID|invalid)/);
});

test('--previous: a receipt that does not follow the one supplied heads INVALID for the chain link, with the signature valid', () => {
  for (const extra of [{}, { previousReceiptHash: `sha256:${sha(first.payload)}` }]) {
    const r = run(write(sign(fields(2, extra))), '--key', publicKey, '--previous', firstPath);
    assert.equal(r.status, 1, JSON.stringify(extra));
    assert.match(r.stdout, /^✗ INVALID: chain link does not follow the previous receipt \(chain_break\)$/m);
    assert.match(r.stdout, /^ {2}Signature: {2}valid$/m);
  }
});

test('a check that could not run heads NOT CHECKED and names it', () => {
  const r = run(firstPath);
  assert.equal(r.status, 2);
  assert.match(r.stdout, /^\? NOT CHECKED: no key was given to check the signature \(no_public_key\)$/m);
  assert.match(r.stdout, /^ {2}Signature: {2}not checked \(no_public_key\)$/m);
});

/** A JSONL file of receipts, each linked to the one before unless it carries its own previousReceiptHash. */
function chain(...receipts) {
  const out = [];
  for (const { extra = {}, key = secret } of receipts) {
    const link = out.length && !('previousReceiptHash' in extra) ? { previousReceiptHash: `sha256:${sha(out[out.length - 1])}` } : {};
    out.push(sign(fields(out.length + 1, { ...link, ...extra }), key));
  }
  return write(out.map((r) => JSON.stringify(r)).join('\n') + '\n', `chain${n++}.jsonl`);
}

test('replay heads VALID with the receipts and chains it read', () => {
  const r = run('--replay-chain', chain({}, {}), '--key', publicKey);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^✓ VALID: 2 receipts in 1 chain, every check passed$/m);
});

test('replay heads INVALID for the first failing line and its check: a chain break, a key window, a bad signature', () => {
  const broken = run('--replay-chain', chain({}, { extra: { previousReceiptHash: `sha256:${'0'.repeat(64)}` } }), '--key', publicKey);
  assert.equal(broken.status, 1);
  assert.match(broken.stdout, /^✗ INVALID: line 2: chain link does not follow the previous receipt \(chain_break\)$/m);
  const outside = run('--replay-chain', chain({}, { extra: { issued_at: '2026-07-01T00:00:00Z' } }), '--jwks', keys);
  assert.equal(outside.status, 1);
  assert.match(outside.stdout, /^✗ INVALID: line 2: key outside its validity window \(key_outside_validity_window\)$/m);
  const forged = run('--replay-chain', chain({ key: other }, {}), '--key', publicKey);
  assert.equal(forged.status, 1);
  assert.match(forged.stdout, /^✗ INVALID: line 1: the signature does not verify under the key used \(invalid_signature\)$/m);
});

test('replay heads NOT CHECKED for the first line that could not be checked', () => {
  const r = run('--replay-chain', chain({}, {}));
  assert.equal(r.status, 2);
  assert.match(r.stdout, /^\? NOT CHECKED: line 1: no key was given to check the signature \(no_public_key\)$/m);
});
