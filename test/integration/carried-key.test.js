/**
 * A carried key (0.10.27): the value of a public_key, verification_key or verification_jwk member of the signed
 * bytes. A verifier never verifies with one, and when a key from a trust anchor outside the receipt is used, a carried
 * key that is not that key makes the receipt invalid (key_mismatch, exit 1), whether the key came from --key or
 * --jwks. 0.10.26 searched the signed bytes for such members only when no key was supplied, so a receipt signed by the
 * anchored key and carrying another key's public_key was valid under both.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../../src/util/canonical.js';
import { carriedKeyCheck, verifyReceipt } from '../../src/engines/ed25519-receipt.js';
import { verifyReceiptText } from '../../src/browser.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const secret = new Uint8Array(32).fill(0x42);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const other = bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(0x07)));
const KID = 'sb:issuer:TESTKEY00001';
const b64url = (hex) => Buffer.from(hex, 'hex').toString('base64url');
const signHex = (value, key = secret) => bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(value)), key));
const base = { type: 'protectmcp:decision', tool_name: 'x', decision: 'allow', issued_at: '2026-03-22T14:32:04.102Z', issuer_id: KID };
const envelope = (payload, key = secret) => ({ payload, signature: { alg: 'EdDSA', kid: KID, sig: signHex(payload, key) } });

const dir = mkdtempSync(join(tmpdir(), 'acta-carried-key-'));
const write = (name, value) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(value)); return p; };
const jwks = write('jwks.json', { keys: [{ kty: 'OKP', crv: 'Ed25519', kid: KID, x: b64url(publicKey), use: 'sig' }] });
const run = (...args) => spawnSync(process.execPath, [cli, ...args, '--json'], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
const json = (...args) => { const r = run(...args); return { status: r.status, report: JSON.parse(r.stdout) }; };

test('cli: signed by the anchored key, carrying another public_key: invalid under --key and --jwks', () => {
  const file = write('21.json', envelope({ ...base, public_key: other }));
  for (const keyArgs of [['--key', publicKey], ['--jwks', jwks]]) {
    const { status, report } = json(file, ...keyArgs);
    assert.equal(status, 1, `${keyArgs[0]}: ${JSON.stringify(report)}`);
    assert.equal(report.outcome, 'invalid');
    assert.equal(report.error, 'key_mismatch');
    assert.equal(report.checks.signature.result, 'pass', 'the signature itself verifies');
    assert.deepEqual(report.checks.carried_key, { result: 'fail', code: 'key_mismatch' });
    assert.match(report.detail, /carry public_key/);
  }
});

test('cli: a receipt that carries the anchored key itself stays valid, in every form read', () => {
  const forms = [
    ['public_key', publicKey],
    ['public_key', publicKey.toUpperCase()],
    ['verification_key', b64url(publicKey)],
    ['verification_jwk', { kty: 'OKP', crv: 'Ed25519', x: b64url(publicKey) }],
  ];
  for (const [name, value] of forms) {
    const { status, report } = json(write(`same-${name}.json`, envelope({ ...base, [name]: value })), '--key', publicKey);
    assert.equal(status, 0, `${name}: ${JSON.stringify(report)}`);
    assert.deepEqual(report.checks.carried_key, { result: 'pass' });
  }
  // A receipt that carries no key gets no carried-key check at all.
  const none = json(write('none.json', envelope(base)), '--key', publicKey);
  assert.equal(none.status, 0);
  assert.equal(none.report.checks.carried_key, undefined);
});

test('cli: under a key that did not sign it, the signature is still the failure reported', () => {
  const file = write('bystander.json', envelope({ ...base, public_key: other }, new Uint8Array(32).fill(0x07)));
  const { status, report } = json(file, '--key', publicKey);
  assert.equal(status, 1);
  assert.equal(report.error, 'invalid_signature');
  assert.equal(report.checks.carried_key.result, 'fail');
  // With no key at all the carried key is still refused as a key, as before (undecidable).
  const none = json(file);
  assert.equal(none.status, 2);
  assert.equal(none.report.error, 'embedded_key_rejected');
});

test('cli: a key in the flat shapes\' signed bytes, top level or a v2 payload, is checked too; replay as well', () => {
  const flat = { ...base, kid: KID, verification_key: other };
  const out = json(write('flat.json', { ...flat, signature: signHex(flat) }), '--key', publicKey);
  assert.equal(out.status, 1, JSON.stringify(out.report));
  assert.equal(out.report.error, 'key_mismatch');
  const v2 = { v: 2, type: 'decision_receipt', algorithm: 'ed25519', kid: KID, issuer: 'test', issued_at: base.issued_at, payload: { decision: 'allow', public_key: other } };
  const v2out = json(write('v2.json', { ...v2, signature: signHex(v2) }), '--key', publicKey);
  assert.equal(v2out.status, 1, JSON.stringify(v2out.report));
  assert.equal(v2out.report.error, 'key_mismatch');
  const chain = join(dir, 'chain.jsonl');
  writeFileSync(chain, `${JSON.stringify(envelope({ ...base, public_key: other }))}\n`);
  const replay = spawnSync(process.execPath, [cli, '--replay-chain', chain, '--key', publicKey, '--json'], { encoding: 'utf8', timeout: 20000 });
  assert.equal(replay.status, 1, replay.stdout);
  assert.equal(JSON.parse(replay.stdout).receipts[0].error, 'key_mismatch');
});

test('unit: carriedKeyCheck reads hex, base64url and JWK keys, and an unreadable value is not the anchored key', () => {
  assert.equal(carriedKeyCheck({ type: 't' }, publicKey), null);
  assert.equal(carriedKeyCheck({ public_key: other }, 'not-a-key'), null, 'no usable anchored key, no check');
  assert.equal(carriedKeyCheck({ public_key: null }, publicKey), null, 'null carries no key');
  assert.deepEqual(carriedKeyCheck({ public_key: publicKey }, publicKey.toUpperCase()), { result: 'pass' });
  assert.equal(carriedKeyCheck({ public_key: other }, publicKey).code, 'key_mismatch');
  assert.equal(carriedKeyCheck({ public_key: 'pem or prose' }, publicKey).code, 'key_mismatch');
  assert.equal(carriedKeyCheck({ verification_jwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' } }, publicKey).code, 'key_mismatch');
  assert.equal(carriedKeyCheck({ public_key: publicKey, verification_key: other }, publicKey).code, 'key_mismatch', 'every carried key must be the anchored one');
  assert.equal(carriedKeyCheck({ payload: { verification_key: b64url(other) } }, publicKey).code, 'key_mismatch');
});

test('engine and browser: the same rule, and keySource names where the key came from', async () => {
  const receipt = envelope({ ...base, public_key: other });
  const r = await verifyReceipt(receipt, 'ed25519-passport', { publicKey, keySource: 'jwks' });
  assert.equal(r.error, 'key_mismatch');
  assert.equal(r.keySource, 'jwks');
  const browser = await verifyReceiptText(JSON.stringify(receipt), publicKey);
  assert.equal(browser.status, 'invalid');
  assert.equal(browser.error, 'key_mismatch');
  const jwksRun = json(write('jwks-source.json', envelope(base)), '--jwks', jwks);
  assert.equal(jwksRun.status, 0);
  assert.equal(jwksRun.report.keySource, 'jwks', 'a key from --jwks is no longer labelled "provided"');
});
