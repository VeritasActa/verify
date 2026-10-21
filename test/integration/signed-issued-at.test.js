/**
 * The key window reads the signed issued_at alone (0.10.27): the payload's in the envelope shape, the top-level one in
 * the flat shapes, as an RFC 3339 string. 0.10.26 fell back to an issued_at or timestamp beside the envelope's
 * payload, which the signature does not cover, and read a number as epoch seconds, so a receipt was placed in its key's
 * window by a value nobody signed, or by a number. Each is now undecidable (key_window_unverifiable, exit 2), as a
 * receipt with no issued_at anywhere already was.
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
const secret = new Uint8Array(32).fill(0x42);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const KID = 'sb:issuer:TESTKEY00001';
const signHex = (value) => bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(value)), secret));
const base = () => ({ type: 'protectmcp:decision', tool_name: 'delete_database', decision: 'deny', issued_at: '2026-03-22T14:32:04.102Z', issuer_id: KID });
const envelope = (payload) => ({ payload, signature: { alg: 'EdDSA', kid: KID, sig: signHex(payload) } });

const dir = mkdtempSync(join(tmpdir(), 'acta-signed-issued-at-'));
const write = (name, value) => { const path = join(dir, name); writeFileSync(path, JSON.stringify(value)); return path; };
const jwks = write('jwks-window.json', { keys: [{ kty: 'OKP', crv: 'Ed25519', kid: KID, x: Buffer.from(publicKey, 'hex').toString('base64url'), valid_from: '2026-01-01T00:00:00Z', valid_until: '2026-06-01T00:00:00Z' }] });
const check = (value) => {
  const r = spawnSync(process.execPath, [cli, write(`r-${Math.random().toString(16).slice(2)}.json`, value), '--jwks', jwks, '--json'], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
  return { status: r.status, report: JSON.parse(r.stdout) };
};
const undecidable = ({ status, report }, label) => {
  assert.equal(status, 2, `${label}: ${JSON.stringify(report)}`);
  assert.equal(report.outcome, 'undecidable', label);
  assert.equal(report.error, 'key_window_unverifiable', label);
  assert.equal(report.keyStatus.result, 'unverifiable', label);
  assert.equal(report.keyStatus.applied, false, label);
  assert.equal(report.checks.signature.result, 'pass', `${label}: the signature itself still verifies`);
};

test('cli: an issued_at beside the envelope\'s payload is not signed, so it does not place the receipt in the window', () => {
  const p = base(); delete p.issued_at;
  const r = envelope(p); r.issued_at = '2026-03-01T00:00:00Z';
  const out = check(r);
  undecidable(out, 'unsigned top-level issued_at');
  assert.equal(out.report.keyStatus.issued_at, null);
  assert.match(out.report.detail, /signed bytes carry no issued_at/);
});

test('cli: a timestamp, signed or not, is never read in place of issued_at', () => {
  const p = base(); delete p.issued_at;
  const beside = envelope(p); beside.timestamp = '2026-03-01T00:00:00Z';
  undecidable(check(beside), 'unsigned top-level timestamp');
  const q = base(); delete q.issued_at; q.timestamp = '2026-03-01T00:00:00Z';
  undecidable(check(envelope(q)), 'signed payload timestamp');
  const flat = { type: 'protectmcp:decision', tool_name: 'x', decision: 'allow', timestamp: '2026-03-01T00:00:00Z', issuer_id: KID, kid: KID };
  undecidable(check({ ...flat, signature: signHex(flat) }), 'flat receipt with a timestamp only');
});

test('cli: a numeric issued_at is not an RFC 3339 string, so the window cannot be applied', () => {
  const out = check(envelope({ ...base(), issued_at: 1772000000 }));
  undecidable(out, 'numeric issued_at');
  assert.equal(out.report.keyStatus.issued_at, 1772000000);
  assert.match(out.report.detail, /is a number, not a timestamp/);
});

test('cli: the signed issued_at still places a receipt in its window, in the envelope and the flat shapes', () => {
  const inside = check(envelope(base()));
  assert.equal(inside.status, 0, JSON.stringify(inside.report));
  assert.equal(inside.report.keyStatus.result, 'inside');
  // An unsigned issued_at beside the payload never overrides the signed one.
  const r = envelope(base()); r.issued_at = '2027-01-01T00:00:00Z';
  const still = check(r);
  assert.equal(still.status, 0, JSON.stringify(still.report));
  assert.equal(still.report.keyStatus.issued_at, '2026-03-22T14:32:04.102Z');
  const flat = { ...base(), kid: KID };
  const flatOut = check({ ...flat, signature: signHex(flat) });
  assert.equal(flatOut.status, 0, JSON.stringify(flatOut.report));
  assert.equal(flatOut.report.keyStatus.result, 'inside');
});

test('cli: replay reads the signed issued_at the same way', () => {
  const p = base(); delete p.issued_at;
  const r = envelope(p); r.issued_at = '2026-03-01T00:00:00Z';
  const chain = join(dir, 'chain.jsonl');
  writeFileSync(chain, `${JSON.stringify(r)}\n`);
  const out = spawnSync(process.execPath, [cli, '--replay-chain', chain, '--jwks', jwks, '--json'], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
  assert.equal(out.status, 2, out.stdout);
  const report = JSON.parse(out.stdout);
  assert.equal(report.receipts[0].error, 'key_window_unverifiable');
});
