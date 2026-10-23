/**
 * Knowledge Units: a KU is checked through the receipts it carries, and its own receipt_sig and receipt_hash are not
 * checked, since draft-farley-acta-knowledge-units-00 §8 (Receipt Binding) does not define their preimage
 * unambiguously and §11 requires it to be recomputed. So a KU is never valid: invalid (exit 1) when a receipt fails,
 * and undecidable (exit 2) otherwise, with the reason named. Before, a KU with receipt_sig "" and no receipts was
 * "Knowledge Unit: VALID, 0/0" (exit 0), so was one whose receipts were skipped, and so was one whose receipts verify
 * while its aggregate went unchecked; and one checked with no key was invalid.
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
const dir = mkdtempSync(join(tmpdir(), 'acta-ku-'));
const write = (name, value) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(value)); return p; };
const run = (...args) => spawnSync(process.execPath, [cli, ...args, '--json'], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
const json = (...args) => { const r = run(...args); return { status: r.status, report: JSON.parse(r.stdout) }; };

const secret = new Uint8Array(32).fill(0x42);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const otherKey = bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(0x07)));
const KID = 'sb:issuer:KUTEST000001';
const receipt = (decision = 'allow') => {
  const payload = { type: 'protectmcp:decision', tool_name: 'answer', decision, issued_at: '2026-04-06T12:00:00.000Z', issuer_id: KID };
  return { payload, signature: { alg: 'EdDSA', kid: KID, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), secret)) } };
};
const ku = (receipts, extra = {}) => ({
  type: 'knowledge_unit', id: 'ku-abcdefghijkl', version: 1, canonical_question: 'Is the sky blue?', consensus_level: 'strong',
  agreed: 'Yes.', models_used: ['a', 'b'], process_template: 'three-round', status: 'active', fresh_until: '2026-07-06',
  receipt_sig: 'aa'.repeat(64), receipt_kid: KID, receipt_hash: 'bb'.repeat(32), ...(receipts ? { receipts } : {}), ...extra,
});

test('cli: a KU with no receipts is undecidable (no_receipts, exit 2), with or without a key', () => {
  const file = write('ku-empty.json', ku(null, { receipt_sig: '' }));
  for (const extra of [[], ['--strict', '--key', otherKey]]) {
    const { status, report } = json(file, ...extra);
    assert.equal(status, 2, `${extra.join(' ')}: ${JSON.stringify(report)}`);
    assert.equal(report.valid, false);
    assert.equal(report.outcome, 'undecidable');
    assert.equal(report.error, 'no_receipts');
  }
});

test('cli: receipts in no format the verifier reads are not checked, so the KU is undecidable (exit 2)', () => {
  const { status, report } = json(write('ku-junk.json', ku([{ foo: 1 }, { bar: 2 }])), '--key', publicKey);
  assert.equal(status, 2, JSON.stringify(report));
  assert.equal(report.error, 'unknown_format');
  assert.equal(report.uncheckedReceipts, 2);
  assert.equal(report.verifiedReceipts, 0);
  // One receipt that verifies beside one that cannot be checked is still undecidable.
  const mixed = json(write('ku-mixed.json', ku([receipt(), { foo: 1 }])), '--key', publicKey);
  assert.equal(mixed.status, 2, JSON.stringify(mixed.report));
  assert.equal(mixed.report.verifiedReceipts, 1);
});

test('cli: a KU whose receipts verify is still undecidable, because its receipt_sig and receipt_hash were not checked', () => {
  const file = write('ku-good.json', ku([receipt(), receipt('deny')]));
  const { status, report } = json(file, '--key', publicKey);
  assert.equal(status, 2, JSON.stringify(report));
  assert.equal(report.valid, false);
  assert.equal(report.outcome, 'undecidable');
  assert.equal(report.error, 'receipt_binding_not_checked');
  assert.match(report.detail, /receipt_sig and receipt_hash were not checked: draft-farley-acta-knowledge-units-00 §8 \(Receipt Binding\)/);
  assert.equal(report.verifiedReceipts, 2);
  assert.ok(report.notChecked.some((n) => /receipt_sig and receipt_hash/.test(n)), JSON.stringify(report.notChecked));
  const text = spawnSync(process.execPath, [cli, file, '--key', publicKey], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', CI: '1' } });
  assert.match(text.stdout, /Knowledge Unit: NOT CHECKED \(receipt_binding_not_checked\)/);
  assert.match(text.stdout, /Not checked:/);
  // With no key its receipts could not be checked: undecidable, not invalid.
  const none = json(file);
  assert.equal(none.status, 2, JSON.stringify(none.report));
  assert.equal(none.report.error, 'no_public_key');
});

test('cli: a KU with a receipt that fails is invalid (exit 1)', () => {
  const bad = receipt();
  bad.payload.decision = 'deny';
  const { status, report } = json(write('ku-bad.json', ku([receipt(), bad])), '--key', publicKey);
  assert.equal(status, 1, JSON.stringify(report));
  assert.equal(report.outcome, 'invalid');
  assert.equal(report.error, 'invalid_signature');
  assert.equal(report.failedReceipts, 1);
});
