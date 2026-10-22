/**
 * Payload notes (0.10.27): what an envelope's payload lacks against §2.2 of the -04 editor's copy (a type, issued_at
 * or issuer_id) and against its declared type (§3), reported beside the result and never counted in the outcome. A
 * protectmcp:decision with no tool_name, or with a decision outside the closed set, stays valid, exit 0, as in 0.10.26,
 * and now says what it lacks. An issuer_id that does not match the kid is not a note: it is invalid
 * (issuer-kid.test.js). Making a missing member change the outcome was held back: receipts that verify today,
 * protect-mcp's commitment-mode receipts among them, would turn invalid.
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
import { envelopePayloadNotes } from '../../src/engines/ed25519-receipt.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const secret = new Uint8Array(32).fill(0x42);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const KID = 'sb:issuer:TESTKEY00001';
const signHex = (value) => bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(value)), secret));
const base = () => ({ type: 'protectmcp:decision', tool_name: 'delete_database', decision: 'deny', issued_at: '2026-03-22T14:32:04.102Z', issuer_id: KID });
const envelope = (payload, signature = {}) => ({ payload, signature: { alg: 'EdDSA', kid: KID, sig: signHex(payload), ...signature } });

const dir = mkdtempSync(join(tmpdir(), 'acta-payload-notes-'));
const check = (receipt) => {
  const file = join(dir, `r-${Math.random().toString(16).slice(2)}.json`);
  writeFileSync(file, JSON.stringify(receipt));
  const r = spawnSync(process.execPath, [cli, file, '--key', publicKey, '--json'], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
  return { status: r.status, report: JSON.parse(r.stdout) };
};

test('cli: a decision outside the closed set, a missing tool_name or a missing §2.2 member stay valid, and are named', () => {
  const noTool = base(); delete noTool.tool_name;
  const noIssuer = base(); delete noIssuer.issuer_id;
  const noTime = base(); delete noTime.issued_at;
  const cases = [
    ['decision "maybe"', envelope({ ...base(), decision: 'maybe' }), /decision "maybe" is not one of allow, deny, rate_limit, require_approval/],
    ['no tool_name', envelope(noTool), /has no tool_name/],
    ['no issuer_id', envelope(noIssuer), /has no issuer_id, which §2\.2/],
    ['no issued_at', envelope(noTime), /has no issued_at, which §2\.2/],
  ];
  for (const [label, receipt, note] of cases) {
    const { status, report } = check(receipt);
    assert.equal(status, 0, `${label}: ${JSON.stringify(report)}`);
    assert.equal(report.outcome, 'valid', label);
    assert.ok(Array.isArray(report.payloadNotes) && report.payloadNotes.some((n) => note.test(n)), `${label}: ${JSON.stringify(report.payloadNotes)}`);
  }
  // A payload that has everything gets no notes.
  const clean = check(envelope(base()));
  assert.equal(clean.status, 0);
  assert.equal(clean.report.payloadNotes, undefined);
});

test('unit: envelopePayloadNotes names each missing §2.2 member and each value outside the declared type\'s set', () => {
  const sig = { alg: 'EdDSA', kid: KID, sig: 'ab' };
  assert.deepEqual(envelopePayloadNotes(base(), sig), []);
  const bare = envelopePayloadNotes({ decision: 'allow' }, sig);
  assert.equal(bare.length, 1);
  assert.match(bare[0], /no type, issued_at or issuer_id/);
  // With no issuer_id, a missing kid is a note too; with one, it is the issuer check's failure, not a note.
  const noKid = { alg: 'EdDSA', sig: 'ab' };
  assert.ok(envelopePayloadNotes({ type: 't', issued_at: base().issued_at }, noKid).some((n) => /has no kid/.test(n)));
  assert.ok(!envelopePayloadNotes(base(), noKid).some((n) => /kid/.test(n)));
  assert.ok(!envelopePayloadNotes({ ...base(), issuer_id: 'someone-else' }, sig).some((n) => /issuer_id/.test(n)));
  const restraint = envelopePayloadNotes({ type: 'protectmcp:restraint', tool_name: 'rm_rf', decision: 'maybe', denial_type: 'other', issued_at: base().issued_at, issuer_id: KID }, sig);
  assert.ok(restraint.some((n) => /has no agent_id or agent_manifest_version/.test(n)), JSON.stringify(restraint));
  assert.ok(restraint.some((n) => /decision "maybe" is not one of allow, deny/.test(n)));
  assert.ok(restraint.some((n) => /denial_type "other"/.test(n)));
  // A type this document does not define has no member list to check, only the common members.
  assert.deepEqual(envelopePayloadNotes({ type: 'example:other', issued_at: base().issued_at, issuer_id: KID }, sig), []);
  assert.deepEqual(envelopePayloadNotes(null, sig), []);
});

test('cli: the flat shapes get no notes, as their rules are still being settled', () => {
  const members = { v: 2, type: 'decision_receipt', algorithm: 'ed25519', kid: KID, issuer: 'test', issued_at: base().issued_at, payload: { decision: 'maybe' } };
  const { status, report } = check({ ...members, signature: signHex(members) });
  assert.equal(status, 0, JSON.stringify(report));
  assert.equal(report.payloadNotes, undefined);
});
