/**
 * Draft §6.6 through the CLI, the way an outside conformance harness runs it (for example the verifier contract in
 * probityai/agent-evidence-vectors): a receipt path, a JWKS file, `--mode receipt --json`, and the exit status.
 * An envelope whose payload carries a signature member is genuinely signed, and is still refused, as invalid (exit 1).
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
const secret = new Uint8Array(32).fill(9);
const publicKey = ed25519.getPublicKey(secret);
const kid = 'test:signing-input';

function run(payload) {
  const dir = mkdtempSync(join(tmpdir(), 'acta-signing-input-'));
  const receipt = {payload, signature: {alg: 'EdDSA', kid, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), secret))}};
  const jwks = {keys: [{kty: 'OKP', crv: 'Ed25519', kid, x: Buffer.from(publicKey).toString('base64url'), use: 'sig'}]};
  writeFileSync(join(dir, 'receipt.json'), JSON.stringify(receipt));
  writeFileSync(join(dir, 'jwks.json'), JSON.stringify(jwks));
  const child = spawnSync(process.execPath, [cli, join(dir, 'receipt.json'), '--jwks', join(dir, 'jwks.json'), '--mode', 'receipt', '--json'], {encoding: 'utf8', timeout: 20000});
  return {status: child.status, report: JSON.parse(child.stdout)};
}

const fields = {type: 'protectmcp:decision', issued_at: '2026-07-15T12:00:00Z', tool_name: 'records.share', decision: 'allow'};

test('cli: a payload carrying "signature": null is invalid (exit 1, signature_in_signing_input)', () => {
  const {status, report} = run({...fields, signature: null});
  assert.equal(report.valid, false);
  assert.equal(report.error, 'signature_in_signing_input');
  assert.equal(status, 1);
});

test('cli: the empty string is refused the same way', () => {
  const {status, report} = run({...fields, signature: ''});
  assert.equal(report.error, 'signature_in_signing_input');
  assert.equal(status, 1);
});

test('cli: the same payload without the member verifies (exit 0)', () => {
  const {status, report} = run(fields);
  assert.equal(report.valid, true);
  assert.equal(status, 0);
});
