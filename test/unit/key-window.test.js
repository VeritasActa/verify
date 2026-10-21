import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../../src/util/canonical.js';
import { checkKeyWindow, receiptIssuedAt, windowOf } from '../../src/util/key-window.js';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'cli.js');
const secret = new Uint8Array(32).fill(9);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const x = Buffer.from(publicKey, 'hex').toString('base64url');
const WINDOW = { valid_from: '2026-01-01T00:00:00Z', valid_until: '2026-06-01T00:00:00Z' };

function receipt(issuedAt) {
  const payload = { type: 'protectmcp:decision', tool_name: 'read_file', decision: 'allow', issued_at: issuedAt, issuer_id: 'k1' };
  return { payload, signature: { alg: 'EdDSA', kid: 'k1', sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), secret)) } };
}

function run(issuedAt, { window = WINDOW, extra = [], key = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'va-keywin-'));
  const file = join(dir, 'receipt.json');
  writeFileSync(file, JSON.stringify(receipt(issuedAt)));
  const jwks = join(dir, 'jwks.json');
  writeFileSync(jwks, JSON.stringify({ keys: [{ kty: 'OKP', crv: 'Ed25519', kid: 'k1', x, ...(window || {}) }] }));
  const keyArgs = key ? ['--key', publicKey] : ['--jwks', jwks];
  const p = spawnSync(process.execPath, [CLI, file, ...keyArgs, '--mode', 'receipt', '--json', '--no-sigil', ...extra], { encoding: 'utf8' });
  return { code: p.status, out: JSON.parse(p.stdout) };
}

test('windowOf reads the JWK window as written and ignores keys without one', () => {
  assert.deepEqual(windowOf({ kid: 'a', ...WINDOW }), WINDOW);
  // An absent bound is left out (open on that side); a null one is kept, and cannot be applied (0.10.26).
  assert.deepEqual(windowOf({ kid: 'a', valid_until: '2026-06-01T00:00:00Z' }), { valid_until: '2026-06-01T00:00:00Z' });
  assert.deepEqual(windowOf({ kid: 'a', valid_from: null }), { valid_from: null });
  assert.equal(windowOf({ kid: 'a' }), null);
});

test('receiptIssuedAt reads only the signed issued_at, as written (0.10.27)', () => {
  const sig = { alg: 'EdDSA', kid: 'k1', sig: 'ab' };
  // The envelope signs its payload alone: the payload's issued_at, and nothing beside it.
  assert.equal(receiptIssuedAt({ payload: { issued_at: '2026-03-15T00:00:00Z' }, signature: sig }), '2026-03-15T00:00:00Z');
  assert.equal(receiptIssuedAt({ payload: {}, issued_at: '2026-03-15T00:00:00Z', signature: sig }), null);
  assert.equal(receiptIssuedAt({ payload: {}, timestamp: '2026-03-15T00:00:00Z', signature: sig }), null);
  assert.equal(receiptIssuedAt({ payload: { timestamp: '2026-03-15T00:00:00Z' }, signature: sig }), null);
  // The flat shapes sign the receipt less its signature: the top-level issued_at, and no timestamp in its place.
  assert.equal(receiptIssuedAt({ v: 2, issued_at: '2026-03-15T00:00:00Z', payload: {}, signature: 'ab' }), '2026-03-15T00:00:00Z');
  assert.equal(receiptIssuedAt({ v: 1, type: 't', timestamp: '2026-03-15T00:00:00Z', signature: 'ab' }), null);
  // Not converted: a number is returned as written, and a window cannot be applied to it.
  assert.equal(receiptIssuedAt({ payload: { issued_at: 1772000000 }, signature: sig }), 1772000000);
  const kw = checkKeyWindow({ window: WINDOW, issuedAt: 1772000000, keySource: 'jwks' });
  assert.equal(kw.status, 'unverifiable');
  assert.equal(kw.error, 'key_window_unverifiable');
  assert.match(kw.detail, /is a number, not a timestamp/);
  assert.equal(receiptIssuedAt({ payload: {}, signature: sig }), null);
});

test('the window is [valid_from, valid_until): inclusive start, exclusive end', () => {
  const at = (issuedAt) => checkKeyWindow({ window: WINDOW, issuedAt, keySource: 'jwks' }).status;
  assert.equal(at('2026-01-01T00:00:00Z'), 'inside');
  assert.equal(at('2026-03-15T00:00:00Z'), 'inside');
  assert.equal(at('2026-05-31T23:59:59.999Z'), 'inside');
  assert.equal(at('2026-06-01T00:00:00Z'), 'outside');
  assert.equal(at('2025-12-31T23:59:59Z'), 'outside');
  assert.equal(checkKeyWindow({ window: { valid_from: 'soon', valid_until: null }, issuedAt: '2026-03-15T00:00:00Z', keySource: 'jwks' }).error, 'key_window_unverifiable');
  assert.equal(checkKeyWindow({ window: { valid_from: '2026-06-01T00:00:00Z', valid_until: '2026-01-01T00:00:00Z' }, issuedAt: '2026-03-15T00:00:00Z', keySource: 'jwks' }).error, 'key_window_unverifiable');
  assert.equal(checkKeyWindow({ window: WINDOW, issuedAt: null, keySource: 'jwks' }).error, 'key_window_unverifiable');
});

test('CLI: a receipt issued inside the window verifies and says so', () => {
  const { code, out } = run('2026-03-15T00:00:00Z');
  assert.equal(code, 0);
  assert.equal(out.valid, true);
  assert.equal(out.keyStatus.result, 'inside');
  assert.equal(out.keyStatus.applied, true);
  assert.deepEqual(out.keyStatus.window, WINDOW);
});

test('CLI: a receipt issued after valid_until is rejected, including exactly at valid_until', () => {
  for (const issuedAt of ['2026-07-15T00:00:00Z', '2026-06-01T00:00:00Z']) {
    const { code, out } = run(issuedAt);
    assert.equal(code, 1, issuedAt);
    assert.equal(out.valid, false);
    assert.equal(out.error, 'key_outside_validity_window');
    assert.equal(out.keyStatus.result, 'outside');
  }
});

test('CLI: a receipt issued before valid_from is rejected', () => {
  const { code, out } = run('2025-12-01T00:00:00Z');
  assert.equal(code, 1);
  assert.equal(out.error, 'key_outside_validity_window');
});

test('CLI: no window in the key source reports validity as not established, and --require-key-window fails it', () => {
  const plain = run('2026-03-15T00:00:00Z', { window: null });
  assert.equal(plain.code, 0);
  assert.equal(plain.out.valid, true);
  assert.equal(plain.out.keyStatus.result, 'no_window');
  assert.equal(plain.out.keyStatus.applied, false);
  const required = run('2026-03-15T00:00:00Z', { window: null, extra: ['--require-key-window'] });
  assert.equal(required.code, 2);
  assert.equal(required.out.valid, false);
  assert.equal(required.out.error, 'key_window_missing');
});

test('CLI: a key pinned with --key carries no window, so validity at issuance is not established; requiring one fails', () => {
  const pinned = run('2026-07-15T00:00:00Z', { key: true });
  assert.equal(pinned.code, 0);
  assert.equal(pinned.out.keyStatus.result, 'not_established');
  assert.equal(pinned.out.checks.key_window.result, 'not_established');
  const required = run('2026-03-15T00:00:00Z', { key: true, extra: ['--require-key-window'] });
  assert.equal(required.out.error, 'key_window_missing');
});

test('CLI: a bad signature is still reported as a bad signature, with the key status beside it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'va-keywin-'));
  const file = join(dir, 'receipt.json');
  const r = receipt('2026-07-15T00:00:00Z');
  r.payload.decision = 'deny';
  writeFileSync(file, JSON.stringify(r));
  const jwks = join(dir, 'jwks.json');
  writeFileSync(jwks, JSON.stringify({ keys: [{ kty: 'OKP', crv: 'Ed25519', kid: 'k1', x, ...WINDOW }] }));
  const p = spawnSync(process.execPath, [CLI, file, '--jwks', jwks, '--mode', 'receipt', '--json', '--no-sigil'], { encoding: 'utf8' });
  const out = JSON.parse(p.stdout);
  assert.equal(out.valid, false);
  assert.equal(out.error, 'invalid_signature');
  assert.equal(out.keyStatus.result, 'outside');
});

test('a key carried at the top level of a v2 receipt is refused like one inside the payload (§9.5)', async () => {
  const { verifyReceipt } = await import('../../src/engines/ed25519-receipt.js');
  const payload = { decision: 'allow', request_id: 'r1', tool: 'http.get' };
  const signed = { v: 2, type: 'decision_receipt', algorithm: 'ed25519', kid: 'k1', issuer: 'test', issued_at: '2026-01-01T00:00:00Z', payload, public_key: publicKey };
  const receipt = { ...signed, signature: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(signed)), secret)) };
  const refused = await verifyReceipt(receipt, 'ed25519-receipt-v2', {});
  assert.equal(refused.valid, false);
  assert.equal(refused.error, 'embedded_key_rejected');
  const pinned = await verifyReceipt(receipt, 'ed25519-receipt-v2', { publicKey });
  assert.equal(pinned.valid, true);
});
