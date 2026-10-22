/**
 * Commitment-mode disclosures (0.10.27). The committed_fields_root is read from the signed bytes: an envelope's
 * payload, where draft §2.2 puts it, or the top level of a flat receipt. A --disclosure-file that cannot be applied is
 * undecidable (disclosure_not_applied, exit 2), never ignored. A proof's leaf count is read as tree_size, the draft §6.5
 * name, with treeSize still accepted. 0.10.26 found a root only at the top level, so an envelope with its root in the
 * payload and a disclosure that cannot match was valid with the file unread, and it read only treeSize, so a correct
 * proof written to §6.5 failed.
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
import { signedCommitment } from '../../src/engines/commitment-mode.js';
import { proofTreeSize, verifyProof, hashLeaf, encodeLeaf } from '../../src/util/merkle.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const secret = new Uint8Array(32).fill(0x42);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const KID = 'sb:issuer:TESTKEY00001';
const signHex = (value) => bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(value)), secret));

// A five-leaf tree built from the draft text (§6.1 to §6.3), not from the verifier's helpers.
const H = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
const leaf = (bytes) => H(Buffer.from([0]), bytes);
const node = (l, r) => H(Buffer.from([1]), l, r);
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const root = (d) => (d.length === 1 ? d[0] : node(root(d.slice(0, split(d.length))), root(d.slice(split(d.length)))));
const path = (m, d) => { if (d.length === 1) return []; const k = split(d.length); return m < k ? [...path(m, d.slice(0, k)), root(d.slice(k))] : [...path(m - k, d.slice(k)), root(d.slice(0, k))]; };
const fields = { action: 'delete_database', amount: 99.5, approver: 'ops-1', principal: 'alice', scope: ['db:write'] };
const names = Object.keys(fields).sort();
const salts = names.map((_, i) => Buffer.alloc(16, i + 1).toString('base64url'));
const leaves = names.map((n, i) => leaf(Buffer.from(canonicalize({ name: n, salt: salts[i], value: fields[n] }), 'utf8')));
const ROOT = root(leaves).toString('hex');
const index = names.indexOf('scope');
const siblings = path(index, leaves).map((b) => b.toString('hex'));
const disclosure = (proof, value = fields.scope) => [{ name: 'scope', value, salt: salts[index], proof }];

const base = { type: 'protectmcp:decision', tool_name: 'x', decision: 'allow', issued_at: '2026-03-22T14:32:04.102Z', issuer_id: KID };
const envelope = (payload) => ({ payload, signature: { alg: 'EdDSA', kid: KID, sig: signHex(payload) } });
const flat = (members) => ({ ...members, signature: signHex(members) });

const dir = mkdtempSync(join(tmpdir(), 'acta-disclosure-'));
const write = (name, value) => { const p = join(dir, name); writeFileSync(p, typeof value === 'string' ? value : JSON.stringify(value)); return p; };
const check = (receipt, disclosureFile, ...extra) => {
  const args = [cli, write(`r-${Math.random().toString(16).slice(2)}.json`, receipt), '--key', publicKey, '--json', ...extra];
  if (disclosureFile !== undefined) args.push('--disclosure-file', disclosureFile);
  const r = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
  return { status: r.status, report: JSON.parse(r.stdout) };
};

test('cli: an envelope\'s root in its payload is found, and the disclosure file is checked against it', () => {
  const receipt = envelope({ ...base, committed_fields_root: ROOT });
  const ok = check(receipt, write('ok.json', disclosure({ index, tree_size: 5, siblings })));
  assert.equal(ok.status, 0, JSON.stringify(ok.report));
  assert.deepEqual(ok.report.disclosedFields, ['scope']);
  assert.equal(ok.report.committedFieldsRoot, ROOT);
  const wrong = check(receipt, write('wrong.json', disclosure({ index, tree_size: 5, siblings }, ['db:read'])));
  assert.equal(wrong.status, 1, JSON.stringify(wrong.report));
  assert.equal(wrong.report.error, 'commitment_mismatch');
});

test('cli: an envelope with its root in the payload and a disclosure that cannot match is checked, not passed unread', () => {
  const receipt = envelope({ ...base, committed_fields_root: 'ab'.repeat(32) });
  const out = check(receipt, write('13.json', [{ name: 'principal', value: 'alice', salt: 'AAAAAAAAAAAAAAAAAAAAAA', proof: { index: 0, tree_size: 1, siblings: [] } }]));
  assert.equal(out.status, 1, JSON.stringify(out.report));
  assert.equal(out.report.outcome, 'invalid');
  assert.equal(out.report.error, 'commitment_mismatch');
});

test('cli: a disclosure file that cannot be applied is undecidable (exit 2), never ignored', () => {
  const committed = envelope({ ...base, committed_fields_root: ROOT });
  const cases = [
    ['no root in the signed bytes', envelope(base), write('d1.json', disclosure({ index, tree_size: 5, siblings }))],
    ['a file that does not exist', committed, join(dir, 'missing.json')],
    ['a file that is not JSON', committed, write('bad.json', 'not json')],
    ['a file with no disclosure', committed, write('empty.json', [])],
  ];
  for (const [label, receipt, file] of cases) {
    const out = check(receipt, file);
    assert.equal(out.status, 2, `${label}: ${JSON.stringify(out.report)}`);
    assert.equal(out.report.outcome, 'undecidable', label);
    assert.equal(out.report.error, 'disclosure_not_applied', label);
    assert.match(out.report.detail, /Nothing in it was verified/, label);
  }
});

test('cli: --disclosure-file is refused (exit 2) where it would be dropped: a bundle, a replay', () => {
  const file = write('d-elsewhere.json', disclosure({ index, tree_size: 5, siblings }));
  const bundle = write('bundle.json', { receipts: [envelope({ ...base, committed_fields_root: ROOT })], verification: { signing_keys: [] } });
  const asBundle = spawnSync(process.execPath, [cli, bundle, '--key', publicKey, '--disclosure-file', file], { encoding: 'utf8', timeout: 20000 });
  assert.equal(asBundle.status, 2);
  assert.match(asBundle.stderr, /does not apply/);
  const chain = join(dir, 'chain.jsonl');
  writeFileSync(chain, `${JSON.stringify(envelope({ ...base, committed_fields_root: ROOT }))}\n`);
  const replay = spawnSync(process.execPath, [cli, '--replay-chain', chain, '--key', publicKey, '--disclosure-file', file], { encoding: 'utf8', timeout: 20000 });
  assert.equal(replay.status, 2);
  assert.match(replay.stderr, /does not apply to --replay-chain/);
});

test('cli: a root beside an envelope\'s payload is outside the signature, so disclosures are not checked against it', () => {
  const receipt = envelope(base);
  receipt.committed_fields_root = ROOT;
  const out = check(receipt, write('unsigned-root.json', disclosure({ index, tree_size: 5, siblings })));
  assert.equal(out.status, 2, JSON.stringify(out.report));
  assert.equal(out.report.error, 'disclosure_not_applied');
  assert.equal(out.report.disclosedFields, undefined);
  // Without a disclosure file such a receipt is an ordinary valid receipt, and the unsigned root is not reported.
  const plain = check(receipt);
  assert.equal(plain.status, 0, JSON.stringify(plain.report));
  assert.equal(plain.report.committedFieldsRoot, undefined);
});

test('cli: a failure already counted outweighs a disclosure file that cannot be applied', () => {
  const receipt = envelope({ ...base, committed_fields_root: ROOT });
  receipt.payload.decision = 'deny';
  const out = check(receipt, join(dir, 'missing.json'));
  assert.equal(out.status, 1, JSON.stringify(out.report));
  assert.equal(out.report.error, 'invalid_signature');
});

test('cli: a flat receipt\'s proof is read as tree_size (draft §6.5), and treeSize still', () => {
  const receipt = flat({ ...base, kid: KID, committed_fields_root: ROOT });
  const snake = check(receipt, write('tree_size.json', disclosure({ index, tree_size: 5, siblings })));
  assert.equal(snake.status, 0, JSON.stringify(snake.report));
  assert.deepEqual(snake.report.disclosedFields, ['scope']);
  const camel = check(receipt, write('treeSize.json', disclosure({ index, treeSize: 5, siblings })));
  assert.equal(camel.status, 0, JSON.stringify(camel.report));
  const tampered = [...siblings]; tampered[0] = 'ff'.repeat(32);
  const bad = check(receipt, write('tampered.json', disclosure({ index, tree_size: 5, siblings: tampered })));
  assert.equal(bad.status, 1);
  assert.equal(bad.report.error, 'commitment_mismatch');
  const both = check(receipt, write('both.json', disclosure({ index, tree_size: 5, treeSize: 4, siblings })));
  assert.equal(both.status, 1, 'a proof that gives two different sizes gives none');
});

test('unit: proofTreeSize and signedCommitment', () => {
  assert.equal(proofTreeSize({ tree_size: 5 }), 5);
  assert.equal(proofTreeSize({ treeSize: 5 }), 5);
  assert.equal(proofTreeSize({ tree_size: 5, treeSize: 5 }), 5);
  assert.equal(proofTreeSize({ tree_size: 5, treeSize: 4 }), null);
  assert.equal(proofTreeSize({ tree_size: 2.5 }), null);
  assert.equal(proofTreeSize({ tree_size: '5' }), null);
  assert.equal(proofTreeSize({}), null);
  const leafHash = hashLeaf(encodeLeaf('scope', salts[index], fields.scope));
  assert.equal(verifyProof(ROOT, leafHash, { index, tree_size: 5, siblings }), true);
  assert.equal(verifyProof(ROOT, leafHash, { index, treeSize: 5, siblings }), true);
  const sig = { alg: 'EdDSA', kid: KID, sig: 'ab' };
  assert.equal(signedCommitment({ payload: { committed_fields_root: ROOT }, signature: sig }).root, ROOT);
  assert.equal(signedCommitment({ payload: {}, committed_fields_root: ROOT, signature: sig }), null);
  assert.equal(signedCommitment({ committed_fields_root: ROOT, signature: 'ab' }).root, ROOT);
  assert.equal(signedCommitment({ v: 2, payload: { committed_fields_root: ROOT }, signature: 'ab' }).root, ROOT);
  assert.equal(signedCommitment({ payload: { committed_fields_root: '' }, signature: sig }), null);
});
