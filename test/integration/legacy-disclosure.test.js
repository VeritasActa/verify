/**
 * AIP-0002 selective disclosure (--disclose field:salt:value) against the _commitments map the signature covers
 * (0.10.27): the payload's in the envelope shape, the top-level one (or a v2 payload's) in the flat shapes. A map
 * beside an envelope's payload is outside the signature, so it is not read, and a --disclose that cannot be applied is
 * undecidable (disclosure_not_applied, exit 2), as a --disclosure-file is. 0.10.26 read the top level of every
 * receipt, so an envelope's disclosures were checked against a map nobody signed, and a --disclose with nothing to
 * check it against was ignored (exit 0).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../../src/util/canonical.js';
import { signedLegacyCommitments } from '../../src/engines/selective-disclosure.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const secret = new Uint8Array(32).fill(0x42);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const KID = 'sb:issuer:TESTKEY00001';
const signHex = (value) => bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(value)), secret));
// AIP-0002: commitment = SHA-256(salt || JSON(value)), hex, with an optional "sha256:" prefix.
const commit = (salt, value) => `sha256:${createHash('sha256').update(salt + JSON.stringify(value), 'utf8').digest('hex')}`;
const SALT = 'a8f3b2c1d4e5f6a7';
const VALUE = 'PAT-2026-08832';
const commitments = { patient_id: commit(SALT, VALUE) };
const base = { type: 'protectmcp:decision', tool_name: 'x', decision: 'allow', issued_at: '2026-03-22T14:32:04.102Z', issuer_id: KID, patient_id: 'redacted' };
const envelope = (payload) => ({ payload, signature: { alg: 'EdDSA', kid: KID, sig: signHex(payload) } });
const flat = (members) => ({ ...members, signature: signHex(members) });
const disclose = `patient_id:${SALT}:"${VALUE}"`;

const dir = mkdtempSync(join(tmpdir(), 'acta-legacy-disclosure-'));
const check = (receipt, ...extra) => {
  const file = join(dir, `r-${Math.random().toString(16).slice(2)}.json`);
  writeFileSync(file, JSON.stringify(receipt));
  const r = spawnSync(process.execPath, [cli, file, '--key', publicKey, '--json', ...extra], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
  return { status: r.status, report: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr };
};

test('cli: a flat receipt\'s signed top-level _commitments is checked, as before', () => {
  const receipt = flat({ ...base, kid: KID, _commitments: commitments });
  const ok = check(receipt, '--disclose', disclose);
  assert.equal(ok.status, 0, JSON.stringify(ok.report));
  assert.deepEqual(ok.report.disclosedFields, ['patient_id']);
  assert.deepEqual(ok.report.redactedFields, ['patient_id']);
  const wrong = check(receipt, '--disclose', `patient_id:${SALT}:"someone-else"`);
  assert.equal(wrong.status, 1, JSON.stringify(wrong.report));
  assert.equal(wrong.report.error, 'commitment_mismatch');
});

test('cli: an envelope\'s map is read from its payload, the signed bytes', () => {
  const ok = check(envelope({ ...base, _commitments: commitments }), '--disclose', disclose);
  assert.equal(ok.status, 0, JSON.stringify(ok.report));
  assert.deepEqual(ok.report.disclosedFields, ['patient_id']);
});

test('cli: a map beside an envelope\'s payload is outside the signature: not read, and --disclose is not applied (exit 2)', () => {
  const receipt = envelope(base);
  receipt._commitments = commitments;
  const out = check(receipt, '--disclose', disclose);
  assert.equal(out.status, 2, JSON.stringify(out.report));
  assert.equal(out.report.outcome, 'undecidable');
  assert.equal(out.report.error, 'disclosure_not_applied');
  assert.match(out.report.detail, /carry no _commitments map/);
  assert.equal(out.report.disclosedFields, undefined);
  // Without --disclose it is an ordinary valid receipt, and the unsigned map is not reported as committed fields.
  const plain = check(receipt);
  assert.equal(plain.status, 0, JSON.stringify(plain.report));
  assert.equal(plain.report.redactedFields, undefined);
});

test('cli: --disclose with nothing to check, or a value that does not parse, is undecidable (exit 2)', () => {
  const none = check(envelope(base), '--disclose', disclose);
  assert.equal(none.status, 2, JSON.stringify(none.report));
  assert.equal(none.report.error, 'disclosure_not_applied');
  const bad = check(flat({ ...base, kid: KID, _commitments: commitments }), '--disclose', 'patient_id-without-salt');
  assert.equal(bad.status, 2, JSON.stringify(bad.report));
  assert.equal(bad.report.error, 'disclosure_not_applied');
  assert.match(bad.report.detail, /not field:salt:value/);
});

test('cli: --disclose is refused (exit 2) where it would be dropped', () => {
  const chain = join(dir, 'chain.jsonl');
  writeFileSync(chain, `${JSON.stringify(envelope({ ...base, _commitments: commitments }))}\n`);
  const replay = spawnSync(process.execPath, [cli, '--replay-chain', chain, '--key', publicKey, '--disclose', disclose], { encoding: 'utf8', timeout: 20000 });
  assert.equal(replay.status, 2);
  assert.match(replay.stderr, /--disclose checks disclosures against one receipt's commitments, and does not apply to --replay-chain/);
});

test('unit: signedLegacyCommitments reads the signed bytes only', () => {
  const sig = { alg: 'EdDSA', kid: KID, sig: 'ab' };
  assert.deepEqual(signedLegacyCommitments({ payload: { _commitments: commitments }, signature: sig }).commitments, commitments);
  assert.equal(signedLegacyCommitments({ payload: {}, _commitments: commitments, signature: sig }), null);
  assert.deepEqual(signedLegacyCommitments({ _commitments: commitments, signature: 'ab' }).commitments, commitments);
  assert.deepEqual(signedLegacyCommitments({ v: 2, payload: { _commitments: commitments }, signature: 'ab' }).commitments, commitments);
  assert.equal(signedLegacyCommitments({ _commitments: 'not a map', signature: 'ab' }), null);
});
