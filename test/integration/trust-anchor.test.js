/**
 * --trust-anchor was listed as a key source from 0.5.1 and never read: a plain receipt was refused for want of a key,
 * while a self-keyed bundle, a Gate record or an embedded key verified against the keys it carried, exit 0. The flag
 * is now refused on every path (exit 2) before anything is verified.
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

const root = fileURLToPath(new URL('../..', import.meta.url));
const cli = join(root, 'cli.js');
const secret = new Uint8Array(32).fill(41);
const run = (args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });

const dir = mkdtempSync(join(tmpdir(), 'acta-trust-anchor-'));
const payload = { type: 'protectmcp:decision', tool_name: 'records.read', decision: 'allow', issued_at: '2026-10-19T00:00:00Z' };
const receipt = { payload, signature: { alg: 'EdDSA', kid: 'test:anchor', sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), secret)) } };
writeFileSync(join(dir, 'receipt.json'), JSON.stringify(receipt));
writeFileSync(join(dir, 'receipts.jsonl'), `${JSON.stringify(receipt)}\n`);
// An anchor naming a key that signed none of the inputs below.
writeFileSync(join(dir, 'anchor.json'), JSON.stringify({ keys: [{ kty: 'OKP', crv: 'Ed25519', kid: 'other', x: Buffer.from(ed25519.getPublicKey(new Uint8Array(32).fill(43))).toString('base64url') }] }));
const anchor = join(dir, 'anchor.json');

function refused(args, name) {
  const r = run(args);
  assert.equal(r.status, 2, `${name}: ${r.stdout}${r.stderr}`);
  assert.equal(r.stdout, '', name);
  assert.match(r.stderr, /--trust-anchor is not implemented/, name);
  assert.match(r.stderr, /Nothing was verified \(exit 2\)/, name);
}

test('cli: --trust-anchor is refused (exit 2) for a receipt, a self-keyed bundle and a Gate bundle', () => {
  refused([join(dir, 'receipt.json'), '--trust-anchor', anchor, '--json'], 'receipt');
  refused([join(dir, 'receipt.json'), '--trust-anchor', anchor, '--key', bytesToHex(ed25519.getPublicKey(secret))], 'receipt with --key');
  // These verified against the keys they carry (exit 0) while the anchor was ignored.
  refused([join(root, 'samples', 'sample-bundle.json'), '--trust-anchor', anchor, '--json'], 'audit bundle');
  refused([join(root, 'samples', 'sample-gate-bundle.json'), '--trust-anchor', anchor], 'gate bundle');
});

test('cli: --trust-anchor is refused on the replay and explore paths, and with no file given', () => {
  refused(['--replay-chain', join(dir, 'receipts.jsonl'), '--trust-anchor', anchor], 'replay');
  refused(['chain', 'explore', join(dir, 'receipt.json'), '--trust-anchor', anchor], 'explore');
  refused([join(dir, 'receipt.json'), '--trust-anchor'], 'no value');
});

test('the key hints no longer name --trust-anchor', () => {
  const r = run([join(dir, 'receipt.json'), '--json']);
  assert.equal(r.status, 2);
  const report = JSON.parse(r.stdout);
  assert.equal(report.error, 'no_public_key');
  assert.doesNotMatch(report.errorMeta.hint, /trust-anchor/);
  assert.match(report.errorMeta.hint, /--key/);
});
