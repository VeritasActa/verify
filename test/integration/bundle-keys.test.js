/**
 * An audit bundle's own keys (0.10.27). The keys in verification.signing_keys arrive in the file being verified, so
 * they are not a trust anchor: without --key or --jwks the receipts are undecidable (no_public_key, exit 2), and only
 * --trust-bundle-keys checks them with the keys the bundle carries, reported as keySource "bundle", never "provided".
 * 0.10.26 used those keys by default and printed "Bundle: VALID" (exit 0) for a bundle that named its own key.
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
import { verifyBundle } from '../../src/engines/ed25519-receipt.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const secret = new Uint8Array(32).fill(0x42);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const KID = 'sb:issuer:TESTKEY00001';
const x = Buffer.from(publicKey, 'hex').toString('base64url');
const sign = (payload) => ({ payload, signature: { alg: 'EdDSA', kid: KID, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), secret)) } });
const payload = (n) => ({ type: 'protectmcp:decision', tool_name: `tool_${n}`, decision: 'deny', issued_at: `2026-03-22T14:32:0${n}.000Z`, issuer_id: KID });
// A bundle whose verification block carries the key that signed its receipts, in the same file.
const bundle = (receipts = [sign(payload(1)), sign(payload(2))]) => ({ receipts, verification: { signing_keys: [{ kty: 'OKP', crv: 'Ed25519', kid: KID, x }] } });

const dir = mkdtempSync(join(tmpdir(), 'acta-bundle-keys-'));
const write = (name, value) => { const path = join(dir, name); writeFileSync(path, JSON.stringify(value)); return path; };
const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
const json = (...args) => { const r = run(...args, '--json'); return { status: r.status, report: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr }; };

test('cli: a bundle that carries its own key is not checked without a key from outside it (exit 2, no_public_key)', () => {
  const file = write('own-key.json', bundle());
  const { status, report } = json(file);
  assert.equal(status, 2, JSON.stringify(report));
  assert.equal(report.valid, false);
  assert.equal(report.outcome, 'undecidable');
  assert.equal(report.error, 'no_public_key');
  assert.equal(report.keySource, null);
  assert.equal(report.undecidable, 2);
  assert.equal(report.failed, 0);
  for (const r of report.receipts) {
    assert.equal(r.outcome, 'undecidable');
    assert.equal(r.error, 'no_public_key');
    assert.notEqual(r.keySource, 'provided');
  }
  assert.match(report.detail, /not a trust anchor/);
  const text = run(file);
  assert.equal(text.status, 2);
  assert.match(text.stdout, /Bundle: NOT CHECKED \(no_public_key\)/);
  assert.doesNotMatch(text.stdout, /Bundle: VALID/);
});

test('cli: --trust-bundle-keys checks the receipts with the bundle\'s keys and labels them "bundle", never "provided"', () => {
  const { status, report } = json(write('trusted.json', bundle()), '--trust-bundle-keys');
  assert.equal(status, 0, JSON.stringify(report));
  assert.equal(report.outcome, 'valid');
  assert.equal(report.keySource, 'bundle');
  assert.deepEqual(report.receipts.map((r) => r.keySource), ['bundle', 'bundle']);
  assert.match(report.warning, /not that those keys are the issuer's/);
  // --strict disables the compatibility mode, as it disables --allow-embedded-key.
  const strict = json(write('trusted-strict.json', bundle()), '--trust-bundle-keys', '--strict');
  assert.equal(strict.status, 2);
  assert.equal(strict.report.error, 'no_public_key');
  assert.match(strict.stderr, /--strict overrides --trust-bundle-keys/);
});

test('cli: --key checks a bundle, and a tampered receipt in it makes the bundle invalid (exit 1)', () => {
  const ok = json(write('keyed.json', bundle()), '--key', publicKey);
  assert.equal(ok.status, 0, JSON.stringify(ok.report));
  assert.equal(ok.report.keySource, 'provided');
  const tampered = bundle();
  tampered.receipts[1].payload.decision = 'allow';
  const bad = json(write('tampered.json', tampered), '--key', publicKey);
  assert.equal(bad.status, 1, JSON.stringify(bad.report));
  assert.equal(bad.report.outcome, 'invalid');
  assert.equal(bad.report.error, 'invalid_signature');
  assert.equal(bad.report.failed, 1);
  assert.equal(bad.report.passed, 1);
});

test('cli: --trust-bundle-keys is refused where it does not apply (exit 2), not dropped', () => {
  const receipt = write('receipt.json', sign(payload(1)));
  const single = run(receipt, '--trust-bundle-keys', '--key', publicKey);
  assert.equal(single.status, 2);
  assert.match(single.stderr, /does not apply/);
  const chain = join(dir, 'chain.jsonl');
  writeFileSync(chain, `${JSON.stringify(sign(payload(1)))}\n`);
  const replay = run('--replay-chain', chain, '--trust-bundle-keys', '--key', publicKey);
  assert.equal(replay.status, 2);
  assert.match(replay.stderr, /does not apply to --replay-chain/);
});

test('cli: --jwks gives each receipt the key its own kid names, with that key\'s window', () => {
  // Two issuers in one bundle. 0.10.26 gave every receipt the key set's first key, so the second failed its signature.
  const secretB = new Uint8Array(32).fill(0x07);
  const publicKeyB = bytesToHex(ed25519.getPublicKey(secretB));
  const KID_B = 'sb:issuer:TESTKEY00002';
  const signB = (p) => ({ payload: p, signature: { alg: 'EdDSA', kid: KID_B, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(p)), secretB)) } });
  const two = { receipts: [sign(payload(1)), signB({ ...payload(2), issuer_id: KID_B })], verification: { signing_keys: [] } };
  const keyA = { kty: 'OKP', crv: 'Ed25519', kid: KID, x };
  const keyB = { kty: 'OKP', crv: 'Ed25519', kid: KID_B, x: Buffer.from(publicKeyB, 'hex').toString('base64url') };
  const both = write('jwks-both.json', { keys: [keyA, keyB] });
  const ok = json(write('two-issuers.json', two), '--jwks', both);
  assert.equal(ok.status, 0, JSON.stringify(ok.report));
  assert.equal(ok.report.keySource, 'jwks');
  assert.deepEqual(ok.report.receipts.map((r) => [r.keySource, r.outcome]), [['jwks', 'valid'], ['jwks', 'valid']]);
  // A kid the set lacks leaves that receipt undecidable, naming the kid; nothing falls back to the bundle's own keys.
  const onlyA = write('jwks-a.json', { keys: [keyA] });
  const missing = json(write('two-issuers-b.json', two), '--jwks', onlyA, '--trust-bundle-keys');
  assert.equal(missing.status, 2, JSON.stringify(missing.report));
  assert.equal(missing.report.receipts[1].error, 'jwks_fetch_failed');
  assert.match(missing.report.errors.join(' '), /No key with kid "sb:issuer:TESTKEY00002"/);
  // The window of the key the set gives is applied to each receipt's signed issued_at.
  const closed = write('jwks-window.json', { keys: [{ ...keyA, valid_from: '2026-01-01T00:00:00Z', valid_until: '2026-03-01T00:00:00Z' }, keyB] });
  const outside = json(write('two-issuers-c.json', two), '--jwks', closed);
  assert.equal(outside.status, 1, JSON.stringify(outside.report));
  assert.equal(outside.report.receipts[0].error, 'key_outside_validity_window');
  assert.equal(outside.report.receipts[0].keyStatus.result, 'outside');
  assert.equal(outside.report.receipts[1].outcome, 'valid');
  // A key set that cannot be read checks nothing (exit 2).
  const unreadable = json(write('two-issuers-d.json', two), '--jwks', join(dir, 'no-such-jwks.json'));
  assert.equal(unreadable.status, 2);
  assert.equal(unreadable.report.error, 'jwks_fetch_failed');
});

test('engine: verifyBundle reads no key from the bundle unless trustBundleKeys is set', async () => {
  const untrusted = await verifyBundle(bundle());
  assert.equal(untrusted.outcome, 'undecidable');
  assert.equal(untrusted.error, 'no_public_key');
  const trusted = await verifyBundle(bundle(), { trustBundleKeys: true });
  assert.equal(trusted.outcome, 'valid');
  assert.equal(trusted.receipts[0].keySource, 'bundle');
  // A key given by the caller wins over the bundle's, and keeps its own label.
  const pinned = await verifyBundle(bundle(), { trustBundleKeys: true, publicKey: '11'.repeat(32) });
  assert.equal(pinned.outcome, 'invalid');
  assert.equal(pinned.receipts[0].keySource, 'provided');
  assert.equal(pinned.warning, undefined);
});
