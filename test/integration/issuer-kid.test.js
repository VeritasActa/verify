/**
 * The issuer check (0.10.27). §2.2 of the -04 editor's copy says an envelope's issuer_id "MUST match the kid field in
 * the signature object". As the draft now reads it, a payload that names an issuer_id that is not signature.kid, or
 * names one while the signature object has no kid, is invalid (issuer_kid_mismatch, exit 1). A payload with no
 * issuer_id is not checked; payloadNotes names the gap and the outcome does not change. 0.10.26 never compared the
 * two, so a receipt whose payload named another issuer, or whose signature object named no key, was valid.
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
import { issuerKidCheck } from '../../src/engines/ed25519-receipt.js';
import { verifyReceiptText } from '../../src/browser.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const secret = new Uint8Array(32).fill(0x42);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const KID = 'sb:issuer:TESTKEY00001';
const signHex = (value, key = secret) => bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(value)), key));
const base = () => ({ type: 'protectmcp:decision', tool_name: 'delete_database', decision: 'deny', issued_at: '2026-03-22T14:32:04.102Z', issuer_id: KID });
const envelope = (payload, key = secret) => ({ payload, signature: { alg: 'EdDSA', kid: KID, sig: signHex(payload, key) } });

const dir = mkdtempSync(join(tmpdir(), 'acta-issuer-kid-'));
const write = (name, value) => { const p = join(dir, name); writeFileSync(p, typeof value === 'string' ? value : JSON.stringify(value)); return p; };
const jwks = write('jwks.json', { keys: [{ kty: 'OKP', crv: 'Ed25519', kid: KID, x: Buffer.from(publicKey, 'hex').toString('base64url') }] });
const run = (...args) => spawnSync(process.execPath, [cli, ...args, '--json'], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
const json = (...args) => { const r = run(...args); return { status: r.status, report: JSON.parse(r.stdout) }; };

test('cli: an issuer_id that is not signature.kid is invalid (issuer_kid_mismatch, exit 1), under --key and --jwks', () => {
  const file = write('other-issuer.json', envelope({ ...base(), issuer_id: 'sb:issuer:SOMEONEELSE1' }));
  for (const keyArgs of [['--key', publicKey], ['--jwks', jwks]]) {
    const { status, report } = json(file, ...keyArgs);
    assert.equal(status, 1, `${keyArgs[0]}: ${JSON.stringify(report)}`);
    assert.equal(report.outcome, 'invalid');
    assert.equal(report.error, 'issuer_kid_mismatch');
    assert.equal(report.checks.signature.result, 'pass', 'the signature itself verifies');
    assert.deepEqual(report.checks.issuer_kid, { result: 'fail', code: 'issuer_kid_mismatch' });
    assert.match(report.detail, /is not signature\.kid/);
  }
  const text = spawnSync(process.execPath, [cli, file, '--key', publicKey], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
  assert.equal(text.status, 1);
  assert.match(text.stdout, /INVALID: the payload's issuer_id is not the signature's kid \(issuer_kid_mismatch\)/);
});

test('cli: an issuer_id with no kid to match is invalid; a payload with no issuer_id is valid, with a note', () => {
  const noKid = envelope(base()); delete noKid.signature.kid;
  const out = json(write('no-kid.json', noKid), '--key', publicKey);
  assert.equal(out.status, 1, JSON.stringify(out.report));
  assert.equal(out.report.error, 'issuer_kid_mismatch');
  assert.match(out.report.detail, /has no kid for it to match/);
  const p = base(); delete p.issuer_id;
  const absent = json(write('no-issuer.json', envelope(p)), '--key', publicKey);
  assert.equal(absent.status, 0, JSON.stringify(absent.report));
  assert.equal(absent.report.checks.issuer_kid, undefined);
  assert.ok(absent.report.payloadNotes.some((n) => /has no issuer_id/.test(n)));
  const match = json(write('match.json', envelope(base())), '--key', publicKey);
  assert.equal(match.status, 0);
  assert.deepEqual(match.report.checks.issuer_kid, { result: 'pass' });
});

test('cli: the check needs no key, so it counts beside one that could not run, and a bad signature is still reported first', () => {
  const file = write('no-key.json', envelope({ ...base(), issuer_id: 'sb:issuer:SOMEONEELSE1' }));
  const out = json(file);
  assert.equal(out.status, 1, JSON.stringify(out.report));
  assert.equal(out.report.error, 'issuer_kid_mismatch');
  assert.equal(out.report.checks.signature.result, 'undecidable');
  const tampered = envelope({ ...base(), issuer_id: 'sb:issuer:SOMEONEELSE1' }, new Uint8Array(32).fill(0x07));
  const bad = json(write('bad-signature.json', tampered), '--key', publicKey);
  assert.equal(bad.status, 1);
  assert.equal(bad.report.error, 'invalid_signature');
  assert.equal(bad.report.checks.issuer_kid.result, 'fail');
});

test('cli: the flat shapes are not checked, as their rules are still being settled', () => {
  const flat = { ...base(), issuer_id: 'someone-else', kid: KID };
  const out = json(write('flat.json', { ...flat, signature: signHex(flat) }), '--key', publicKey);
  assert.equal(out.status, 0, JSON.stringify(out.report));
  assert.equal(out.report.checks.issuer_kid, undefined);
});

test('cli and browser: replay and the browser bundle apply it too', async () => {
  const receipt = envelope({ ...base(), issuer_id: 'sb:issuer:SOMEONEELSE1' });
  const chain = join(dir, 'chain.jsonl');
  writeFileSync(chain, `${JSON.stringify(receipt)}\n`);
  const replay = spawnSync(process.execPath, [cli, '--replay-chain', chain, '--key', publicKey, '--json'], { encoding: 'utf8', timeout: 20000 });
  assert.equal(replay.status, 1, replay.stdout);
  assert.equal(JSON.parse(replay.stdout).receipts[0].error, 'issuer_kid_mismatch');
  const browser = await verifyReceiptText(JSON.stringify(receipt), publicKey);
  assert.equal(browser.status, 'invalid');
  assert.equal(browser.error, 'issuer_kid_mismatch');
});

test('unit: issuerKidCheck', () => {
  const sig = { alg: 'EdDSA', kid: KID, sig: 'ab' };
  assert.equal(issuerKidCheck({ type: 't' }, sig), null);
  assert.deepEqual(issuerKidCheck({ issuer_id: KID }, sig), { result: 'pass' });
  assert.equal(issuerKidCheck({ issuer_id: 'other' }, sig).code, 'issuer_kid_mismatch');
  assert.equal(issuerKidCheck({ issuer_id: KID }, { alg: 'EdDSA', sig: 'ab' }).code, 'issuer_kid_mismatch');
  assert.equal(issuerKidCheck({ issuer_id: null }, sig).code, 'issuer_kid_mismatch', 'a present issuer_id that is not the kid, null included');
  assert.equal(issuerKidCheck(null, sig), null);
});
