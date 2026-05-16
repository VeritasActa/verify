/**
 * Unit tests for AIP-0004 snapshot Merkle helper.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSnapshotRoot,
  makeSnapshotPayload,
  makeRollbackPayload,
} from '../../ecosystem/rollback/snapshot.mjs';

test('buildSnapshotRoot: empty input → sha256(empty) b64url', () => {
  const r = buildSnapshotRoot([]);
  // base64url(SHA-256('')) = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
  assert.equal(r, '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU');
});

test('buildSnapshotRoot: deterministic for same inputs', () => {
  const a = buildSnapshotRoot([
    ['src/a.js', Buffer.from('hello')],
    ['src/b.js', Buffer.from('world')],
  ]);
  const b = buildSnapshotRoot([
    ['src/a.js', Buffer.from('hello')],
    ['src/b.js', Buffer.from('world')],
  ]);
  assert.equal(a, b);
});

test('buildSnapshotRoot: path order does not matter (sorted internally)', () => {
  const a = buildSnapshotRoot([
    ['src/a.js', Buffer.from('hello')],
    ['src/b.js', Buffer.from('world')],
  ]);
  const b = buildSnapshotRoot([
    ['src/b.js', Buffer.from('world')],
    ['src/a.js', Buffer.from('hello')],
  ]);
  assert.equal(a, b);
});

test('buildSnapshotRoot: changing one byte changes the root', () => {
  const a = buildSnapshotRoot([['f.txt', Buffer.from('abc')]]);
  const b = buildSnapshotRoot([['f.txt', Buffer.from('abd')]]);
  assert.notEqual(a, b);
});

test('buildSnapshotRoot: changing path changes the root', () => {
  const a = buildSnapshotRoot([['f.txt',  Buffer.from('abc')]]);
  const b = buildSnapshotRoot([['g.txt',  Buffer.from('abc')]]);
  assert.notEqual(a, b);
});

test('buildSnapshotRoot: odd-count layer duplicates last (three files)', () => {
  // Should not throw; returns a well-formed base64url string.
  const r = buildSnapshotRoot([
    ['a', Buffer.from('1')],
    ['b', Buffer.from('2')],
    ['c', Buffer.from('3')],
  ]);
  assert.match(r, /^[A-Za-z0-9_-]{43}$/);
});

test('makeSnapshotPayload: required fields present, optional fields suppressed', () => {
  const p = makeSnapshotPayload({
    session_id: 's-1',
    snapshot_root: 'a'.repeat(43),
    backend: 'copy',
    file_count: 3,
    scope: { allowed_read: ['./src'], allowed_write: ['./src'] },
    issuer_id: 'issuer-1',
    agent_id: 'agent-1',
  });
  assert.equal(p.type, 'snapshot');
  assert.equal(p.session_id, 's-1');
  assert.equal(p.snapshot_backend, 'copy');
  assert.equal(p.file_count, 3);
  assert.ok(!('snapshot_uri' in p));
  assert.ok(!('previousReceiptHash' in p));
  assert.match(p.issued_at, /^\d{4}-\d{2}-\d{2}T/);
});

test('makeSnapshotPayload: optional fields emitted when provided', () => {
  const p = makeSnapshotPayload({
    session_id: 's-2',
    snapshot_root: 'b'.repeat(43),
    backend: 'zfs',
    file_count: 0,
    scope: { allowed_read: [], allowed_write: [], deny: ['./.env'] },
    issuer_id: 'i',
    agent_id: 'a',
    snapshot_uri: 'zfs:pool/dataset@s-2',
    policy_hash: 'p'.repeat(43),
    previousReceiptHash: 'q'.repeat(43),
  });
  assert.equal(p.snapshot_uri, 'zfs:pool/dataset@s-2');
  assert.equal(p.policy_hash, 'p'.repeat(43));
  assert.equal(p.previousReceiptHash, 'q'.repeat(43));
  assert.deepEqual(p.snapshot_scope.deny, ['./.env']);
});

test('makeRollbackPayload: rollback_reason 257 bytes → throws', () => {
  assert.throws(() =>
    makeRollbackPayload({
      session_id: 's',
      snapshot_receipt_hash: 'h'.repeat(43),
      rollback_reason: 'x'.repeat(257),
      rollback_initiator: 'human',
      rollback_outcome: 'success',
      post_rollback_root: 'r'.repeat(43),
      issuer_id: 'i',
      agent_id: 'a',
    })
  , /exceeds 256 bytes/);
});

test('makeRollbackPayload: typical success rollback', () => {
  const p = makeRollbackPayload({
    session_id: 's-3',
    snapshot_receipt_hash: 's'.repeat(43),
    rollback_reason: 'policy-violation detected',
    rollback_initiator: 'policy',
    rollback_outcome: 'success',
    post_rollback_root: 'r'.repeat(43),
    issuer_id: 'i',
    agent_id: 'a',
  });
  assert.equal(p.type, 'rollback');
  assert.equal(p.rollback_outcome, 'success');
  assert.equal(p.rollback_initiator, 'policy');
  assert.ok(!('external_side_effects' in p));
});

test('makeRollbackPayload: partial with external side effects', () => {
  const p = makeRollbackPayload({
    session_id: 's-4',
    snapshot_receipt_hash: 's'.repeat(43),
    rollback_reason: 'partial revert: stripe charge already cleared',
    rollback_initiator: 'human',
    rollback_outcome: 'partial',
    post_rollback_root: 'r'.repeat(43),
    issuer_id: 'i',
    agent_id: 'a',
    external_side_effects: [
      { receipt_hash: 'e'.repeat(43), action: 'stripe.charges.create', compensable: false },
    ],
  });
  assert.equal(p.rollback_outcome, 'partial');
  assert.equal(p.external_side_effects[0].compensable, false);
});
