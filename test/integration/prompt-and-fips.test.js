/**
 * Two results that claimed more than was checked.
 *
 * verify prompt: a receipt or Sigstore bundle that names the prompt's hash proves nothing unless its signature is
 * checked, and verify prompt checks none. Before, an unsigned receipt, or a bundle with no signature at all, that
 * named the hash gave "prompt matches the asserted provenance" (exit 0). It is undecidable now (exit 2).
 *
 * --fips: the algorithm is the one the engine verified, never the file's own unsigned `algorithm` member, and Ed25519
 * is approved (FIPS 186-5). Before, an Ed25519 record labelled ml-dsa-65 passed on its label, and an Ed25519 receipt
 * with its key pinned was refused.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize, sortKeysDeep } from '../../src/util/canonical.js';

const root = fileURLToPath(new URL('../../', import.meta.url));
const cli = join(root, 'cli.js');
const dir = mkdtempSync(join(tmpdir(), 'acta-prompt-fips-'));
const write = (name, value) => { const p = join(dir, name); writeFileSync(p, typeof value === 'string' ? value : JSON.stringify(value)); return p; };
const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
const json = (...args) => { const r = run(...args, '--json'); return { status: r.status, report: JSON.parse(r.stdout) }; };

const prompt = write('CLAUDE.md', 'Always ask before deleting anything.\n');
const promptHash = `sha256:${createHash('sha256').update(readFileSync(prompt)).digest('hex')}`;

test('cli prompt: a hash matched in an unverified receipt or bundle is undecidable (exit 2), never verified provenance', () => {
  const receipt = write('unsigned-receipt.json', { payload: { type: 'prompt-attestation', prompt_hash: promptHash, issued_at: '2026-10-23T00:00:00Z' } });
  const viaReceipt = run('prompt', prompt, '--prompt-receipt', receipt);
  assert.equal(viaReceipt.status, 2, viaReceipt.stdout);
  assert.match(viaReceipt.stdout, /not checked \(signature_not_checked\)/);
  assert.doesNotMatch(viaReceipt.stdout, /matches the asserted provenance/);

  const statement = { _type: 'https://in-toto.io/Statement/v1', subject: [{ name: 'CLAUDE.md', digest: { sha256: promptHash.slice(7) } }] };
  const bundle = write('fake-bundle.json', { dsseEnvelope: { payload: Buffer.from(JSON.stringify(statement)).toString('base64'), signatures: [] } });
  const viaBundle = json('prompt', prompt, '--sigstore-bundle', bundle);
  assert.equal(viaBundle.status, 2, JSON.stringify(viaBundle.report));
  assert.equal(viaBundle.report.error, 'signature_not_checked');

  // A hash the caller supplies is still checked as before, and a receipt naming another hash still fails.
  assert.equal(run('prompt', prompt, '--expected-hash', promptHash).status, 0);
  const other = write('other-receipt.json', { payload: { prompt_hash: `sha256:${'0'.repeat(64)}` } });
  assert.equal(run('prompt', prompt, '--prompt-receipt', other).status, 1);
});

// The report's forged Gate decision, signed by a fresh Ed25519 key, with "algorithm": "ml-dsa-65" added beside it.
const secret = new Uint8Array(32).fill(0x66);
const payload = {
  schema: 'scopeblind.gate.decision/2', proposal_id: 'prop-forged-1', proposal: { symbol: 'AAPL', side: 'buy', qty: 1000000 },
  decision: 'ALLOW', mandate_digest: 'a'.repeat(64), book_digest: 'b'.repeat(64), nav: 100000000, evaluated_at: '2026-10-23T00:00:00Z',
};
const digest = sha256(utf8ToBytes(JSON.stringify(sortKeysDeep(payload))));
const forged = { payload, digest: bytesToHex(digest), signature: bytesToHex(ed25519.sign(digest, secret)), verification_key: bytesToHex(ed25519.getPublicKey(secret)), algorithm: 'ml-dsa-65' };

test('cli --fips: the forged Ed25519 tuple labelled ml-dsa-65 is judged as the Ed25519 it is, not by its label', () => {
  const file = write('gate-forged-mldsa.json', forged);
  // The tuple rests only on the key it carries, so it is accepted only with --allow-carried-key; FIPS mode then judges it.
  assert.equal(json(file, '--fips').status, 2);
  const fips = json(file, '--fips', '--allow-carried-key');
  assert.equal(fips.status, 0, JSON.stringify(fips.report));
  assert.deepEqual(fips.report.fips, { algorithms: ['ed25519'], approved: true }, 'the algorithm FIPS mode read is the one verified');
  // What the label could not do: the carried key is still refused under --strict, and the real key still fails it.
  assert.equal(json(file, '--fips', '--strict').status, 2);
  assert.equal(json(file, '--fips', '--key', bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(0x67)))).status, 1);
});

test('cli --fips: a label passes nothing the engine does not report verifying, and pinned Ed25519 is approved', () => {
  // A Gate evidence bundle names no verified algorithm, so FIPS mode cannot confirm it, whatever it is labelled.
  const bundle = JSON.parse(readFileSync(join(root, 'samples/sample-gate-bundle.json'), 'utf8'));
  const labelled = json(write('gate-bundle-mldsa.json', { ...bundle, algorithm: 'ml-dsa-65' }), '--fips', '--key', bundle.gate_verification_key);
  assert.equal(labelled.status, 2, JSON.stringify(labelled.report));
  assert.equal(labelled.report.error, 'unsupported_algorithm');
  assert.equal(labelled.report.format, 'fips-rejected');

  // An Ed25519 receipt checked with its key is FIPS 186-5 EdDSA.
  const KID = 'sb:issuer:FIPSTEST0001';
  const receiptPayload = { type: 'protectmcp:decision', tool_name: 'x', decision: 'allow', issued_at: '2026-10-23T00:00:00.000Z', issuer_id: KID };
  const receipt = write('receipt.json', { payload: receiptPayload, signature: { alg: 'EdDSA', kid: KID, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(receiptPayload)), secret)) } });
  const pinned = json(receipt, '--fips', '--key', bytesToHex(ed25519.getPublicKey(secret)));
  assert.equal(pinned.status, 0, JSON.stringify(pinned.report));
  assert.deepEqual(pinned.report.fips, { algorithms: ['EdDSA'], approved: true });
});
