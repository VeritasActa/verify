/**
 * A receipt's cosignatures and its authorization.delegation_chain are not checked by the CLI, and its output now says
 * so. Before, a receipt with a junk cosignature and a delegation_chain naming a delegation that does not exist
 * verified (exit 0) and the output mentioned neither, though the 0.5.3 changelog said delegation chains were walked.
 * The outcome does not change: they are reported, not counted.
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

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const dir = mkdtempSync(join(tmpdir(), 'acta-not-checked-'));
const write = (name, text) => { const p = join(dir, name); writeFileSync(p, text); return p; };
const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });

const secret = new Uint8Array(32).fill(0x42);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const KID = 'sb:issuer:COSIGNTEST01';
// The report's V5 receipt: a junk cosignature, and a delegation_chain naming a delegation that does not exist.
const payload = {
  type: 'veritasacta:daemon:decision', spec: 'draft-farley-acta-signed-receipts-03', tool_name: 'wire_transfer',
  tool_input_hash: `sha256:${'1'.repeat(64)}`, decision: 'allow', policy_id: 'p', issued_at: '2026-10-23T00:00:00.000Z',
  issuer_id: KID, sequence: 1, authorization: { delegation_chain: [`sha256:${'d'.repeat(64)}`] },
};
const receipt = {
  payload,
  signature: { alg: 'EdDSA', kid: KID, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), secret)) },
  cosignatures: [{ alg: 'EdDSA', kid: 'server-kid', sig: '00'.repeat(64) }],
};

test('cli: a receipt\'s cosignatures and delegation chain are reported as not checked, and the outcome is unchanged', () => {
  const file = write('receipt.json', JSON.stringify(receipt));
  const r = run(file, '--key', publicKey, '--json');
  assert.equal(r.status, 0, r.stdout);
  const report = JSON.parse(r.stdout);
  assert.equal(report.notChecked.length, 2, JSON.stringify(report.notChecked));
  assert.match(report.notChecked[0], /^cosignatures: 1 present, not checked/);
  assert.match(report.notChecked[1], /^authorization\.delegation_chain: 1 delegation\(s\) named, not checked/);
  assert.match(run(file, '--key', publicKey).stdout, /Not checked .*\n.*cosignatures: 1 present/);

  // In a chain replay each line says so in the warnings; in an audit bundle each receipt does, and the summary counts them.
  const replay = JSON.parse(run('--replay-chain', write('chain.jsonl', `${JSON.stringify(receipt)}\n`), '--key', publicKey, '--json').stdout);
  assert.ok(replay.warnings.some((w) => /^Line 1: cosignatures: 1 present, not checked/.test(w)), JSON.stringify(replay.warnings));
  const bundle = write('bundle.json', JSON.stringify({ receipts: [receipt], verification: { signing_keys: [] } }));
  assert.equal(JSON.parse(run(bundle, '--key', publicKey, '--json').stdout).receipts[0].notChecked.length, 2);
  assert.match(run(bundle, '--key', publicKey).stdout, /Not checked: 1 receipt\(s\) carry cosignatures or a delegation chain/);

  // A receipt that carries neither gets no such note.
  const plain = { payload: { ...payload, authorization: undefined }, signature: receipt.signature };
  delete plain.payload.authorization;
  plain.signature = { ...receipt.signature, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(plain.payload)), secret)) };
  assert.equal(JSON.parse(run(write('plain.json', JSON.stringify(plain)), '--key', publicKey, '--json').stdout).notChecked, undefined);
});
