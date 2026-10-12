/**
 * Draft §6.7 through the CLI, the way an outside conformance harness runs it: a receipt path, a JWKS file,
 * `--mode receipt --json`, and the exit status. A genuinely signed receipt with no predecessor supplied is refused
 * when its link is malformed (exit 1) or names an algorithm other than sha256 (exit 2).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {ed25519} from '@noble/curves/ed25519';
import {bytesToHex, utf8ToBytes} from '@noble/hashes/utils';
import {canonicalize} from '../../src/util/canonical.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const secret = new Uint8Array(32).fill(13);
const publicKey = ed25519.getPublicKey(secret);
const kid = 'test:chain-link';

function run(payload) {
  const dir = mkdtempSync(join(tmpdir(), 'acta-chain-link-'));
  const receipt = {payload, signature: {alg: 'EdDSA', kid, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), secret))}};
  const jwks = {keys: [{kty: 'OKP', crv: 'Ed25519', kid, x: Buffer.from(publicKey).toString('base64url'), use: 'sig'}]};
  writeFileSync(join(dir, 'receipt.json'), JSON.stringify(receipt));
  writeFileSync(join(dir, 'jwks.json'), JSON.stringify(jwks));
  const child = spawnSync(process.execPath, [cli, join(dir, 'receipt.json'), '--jwks', join(dir, 'jwks.json'), '--mode', 'receipt', '--json'], {encoding: 'utf8', timeout: 20000});
  return {status: child.status, report: JSON.parse(child.stdout)};
}

const fields = {type: 'protectmcp:decision', issued_at: '2026-10-12T00:00:00Z', tool_name: 'records.share', decision: 'allow'};

test('cli: "sha256:not-a-digest" is invalid (exit 1, malformed_chain_link)', () => {
  const {status, report} = run({...fields, previousReceiptHash: 'sha256:not-a-digest'});
  assert.equal(report.valid, false);
  assert.equal(report.error, 'malformed_chain_link');
  assert.equal(status, 1);
});

test('cli: a sha512 link is refused (exit 2, unsupported_chain_hash_algorithm)', () => {
  const {status, report} = run({...fields, previousReceiptHash: `sha512:${'ab'.repeat(64)}`});
  assert.equal(report.valid, false);
  assert.equal(report.error, 'unsupported_chain_hash_algorithm');
  assert.equal(status, 2);
});

test('cli: a well-formed link verifies (exit 0)', () => {
  const {status, report} = run({...fields, previousReceiptHash: `sha256:${'ab'.repeat(32)}`});
  assert.equal(report.valid, true);
  assert.equal(report.chainLink, 'sha256');
  assert.equal(status, 0);
});
