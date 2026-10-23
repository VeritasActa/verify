/**
 * Every JSON a verification reads is read as the main input is: a member name given twice is refused, never resolved
 * to its last value. JSON.parse keeps the last and another parser may keep the first, so a receipt with
 * "decision":"deny" before "decision":"allow" can read as two different receipts. The main input was refused (exit 2),
 * but --replay-chain, --diff, the files beside a run manifest, --jwks, chain explore, compliance, verify prompt and
 * --known-issuers used JSON.parse, so the same receipt verified on --replay-chain (exit 0).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../../src/util/canonical.js';

const root = fileURLToPath(new URL('../../', import.meta.url));
const cli = join(root, 'cli.js');
const dir = mkdtempSync(join(tmpdir(), 'acta-duplicate-'));
const write = (name, text) => { const p = join(dir, name); writeFileSync(p, text); return p; };
const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 30000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });

const secret = new Uint8Array(32).fill(0x42);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const KID = 'sb:issuer:DUPTEST00001';
const payload = { type: 'protectmcp:decision', tool_name: 'wire_transfer', decision: 'allow', issued_at: '2026-10-23T00:00:00.000Z', issuer_id: KID };
const receipt = JSON.stringify({ payload, signature: { alg: 'EdDSA', kid: KID, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), secret)) } });
// The report's reproduction: a "decision":"deny" member before the signed "decision":"allow".
const twoDecisions = receipt.replace('"decision":"allow"', '"decision":"deny","decision":"allow"');

test('the strict reader refuses a duplicate member that JSON.parse resolves', async () => {
  const { parseJsonStrict } = await import('../../src/util/strict-json.js');
  assert.equal(typeof parseJsonStrict, 'function');
  assert.equal(JSON.parse(twoDecisions).payload.decision, 'allow');
  assert.throws(() => parseJsonStrict(twoDecisions), (e) => e.code === 'duplicate_key');
  assert.deepEqual(parseJsonStrict(receipt), JSON.parse(receipt));
});

test('cli --replay-chain: a line with a duplicate member is undecidable (exit 2), as the main input is', () => {
  const chain = write('chain.jsonl', `${twoDecisions}\n`);
  const r = run('--replay-chain', chain, '--key', publicKey, '--json');
  assert.equal(r.status, 2, r.stdout);
  const report = JSON.parse(r.stdout);
  assert.equal(report.outcome, 'undecidable');
  assert.equal(report.receipts[0].error, 'malformed_json');
  assert.match(report.errors[0], /Duplicate JSON member: decision/);
  assert.equal(run(write('main.json', twoDecisions), '--key', publicKey).status, 2, 'the main input, as before');
});

test('cli: --diff, the files beside a run manifest and --jwks refuse a duplicate member (exit 2)', () => {
  const plain = write('receipt.json', receipt);
  assert.equal(run(plain, '--diff', write('diff-b.json', twoDecisions)).status, 2);

  const standard = readFileSync(join(root, 'test/fixtures/legate/run-standard.json'), 'utf8');
  const doubled = write('standard-dup.json', standard.replace('"type":', '"type": "x", "type":'));
  const manifest = run(join(root, 'test/fixtures/legate/run-manifest.json'), '--standard', doubled, '--json');
  assert.equal(manifest.status, 2, manifest.stdout + manifest.stderr);
  assert.match(manifest.stderr, /Duplicate JSON member: type/);

  const jwks = JSON.stringify({ keys: [{ kty: 'OKP', crv: 'Ed25519', kid: KID, x: Buffer.from(publicKey, 'hex').toString('base64url') }] });
  assert.equal(run(plain, '--jwks', write('jwks.json', jwks)).status, 0, 'the key set itself is good');
  const r = run(plain, '--jwks', write('jwks-dup.json', jwks.replace('"kty":"OKP"', '"kty":"RSA","kty":"OKP"')), '--json');
  assert.equal(r.status, 2, r.stdout);
  assert.equal(JSON.parse(r.stdout).error, 'jwks_fetch_failed');
});

test('cli: chain explore, compliance, verify prompt and --known-issuers do not read a file with a duplicate member', () => {
  const explored = run('chain', 'explore', write('explore-start.json', twoDecisions), '--json');
  assert.notEqual(explored.status, 0, explored.stdout);
  assert.match(JSON.parse(explored.stdout).error, /cannot_read_starting_receipt:duplicate_key/);

  const receiptsDir = join(dir, 'compliance');
  mkdirSync(receiptsDir);
  writeFileSync(join(receiptsDir, 'r1.json'), twoDecisions);
  const compliance = JSON.parse(run('compliance', '--receipts-dir', receiptsDir, '--json').stdout);
  assert.equal(compliance.manifest.receipts_scanned, 0);
  assert.ok(compliance.warnings.some((w) => /skipped: non-JSON or malformed: r1\.json/.test(w)), JSON.stringify(compliance.warnings));

  const prompt = write('SKILL.md', 'skill');
  const promptReceipt = write('prompt-receipt.json', '{"payload":{"prompt_hash":"x","prompt_hash":"y"}}');
  const p = JSON.parse(run('prompt', prompt, '--prompt-receipt', promptReceipt, '--json').stdout);
  assert.equal(p.error, 'cannot_read_receipt:duplicate_key');

  const tuple = join(root, 'samples/sample-gate-tuple.json');
  const key = JSON.parse(readFileSync(tuple, 'utf8')).verification_key;
  const label = (file) => JSON.parse(run(tuple, '--known-issuers', file, '--json').stdout).signerLabel;
  assert.equal(label(write('issuers.json', JSON.stringify({ [key]: 'Desk A' }))), 'Desk A');
  assert.equal(label(write('issuers-dup.json', `{"${key}":"Desk B","${key}":"Desk A"}`)), undefined);
});
