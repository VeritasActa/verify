/**
 * Unit tests for Rekor / transparency-log anchoring engine (AIP-0005 T4).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';

import {
  computeMerkleRootFromProof,
  computeReceiptHash,
  parseDuration,
  verifyRekorAnchor,
} from '../../src/engines/rekor.js';

// A test log: its key, and a signed checkpoint (c2sp.org/tlog-checkpoint) over a tree size and root hash.
const logSecret = new Uint8Array(32).fill(0x24);
const logKey = bytesToHex(ed25519.getPublicKey(logSecret));
function signedTreeHead(treeSize, rootHex, origin = 'test-log') {
  const text = `${origin}\n${treeSize}\n${Buffer.from(rootHex, 'hex').toString('base64')}\n`;
  const sig = Buffer.concat([Buffer.alloc(4), Buffer.from(ed25519.sign(Buffer.from(text, 'utf-8'), logSecret))]);
  return `${text}\n\u2014 ${origin} ${sig.toString('base64')}\n`;
}

// Helper: build an RFC 6962-style Merkle tree over n leaves, then
// return the root + inclusion proof for a target leaf.
function buildTreeAndProof(leaves, target) {
  // Hash a node per RFC 6962.
  const nodeHash = (left, right) =>
    createHash('sha256')
      .update(Buffer.concat([Buffer.from([0x01]), left, right]))
      .digest();

  // leaf hash = sha256(0x00 || leaf_bytes). For this test we assume
  // the leaves ARE already the 32-byte leaf hashes (not raw bytes),
  // so we do NOT re-apply the 0x00 prefix.

  let layer = leaves.map((l) => Buffer.from(l, 'hex'));
  const siblings = [];
  let index = target;

  while (layer.length > 1) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = i + 1 < layer.length ? layer[i + 1] : layer[i];
      if (i === (index - (index % 2))) {
        // This pair contains our target; record the sibling.
        if (index % 2 === 0) {
          siblings.push(right.toString('hex'));
        } else {
          siblings.push(left.toString('hex'));
        }
      }
      next.push(nodeHash(left, right));
    }
    layer = next;
    index = Math.floor(index / 2);
  }

  return { rootHex: layer[0].toString('hex'), siblings };
}

function leafHash(v) {
  // In tests we use the HASH of v as the "leaf hash" the engine
  // expects (since computeReceiptHash already produces a sha256 hex
  // of the receipt bytes).
  return createHash('sha256').update(Buffer.from(v, 'utf-8')).digest('hex');
}

test('computeMerkleRootFromProof: 2-leaf tree, left leaf', () => {
  const a = leafHash('a');
  const b = leafHash('b');
  const { rootHex, siblings } = buildTreeAndProof([a, b], 0);
  const computed = computeMerkleRootFromProof(a, 0, siblings, 2);
  assert.equal(computed, rootHex);
});

test('computeMerkleRootFromProof: 2-leaf tree, right leaf', () => {
  const a = leafHash('a');
  const b = leafHash('b');
  const { rootHex, siblings } = buildTreeAndProof([a, b], 1);
  const computed = computeMerkleRootFromProof(b, 1, siblings, 2);
  assert.equal(computed, rootHex);
});

test('computeMerkleRootFromProof: 4-leaf tree, each index works', () => {
  const leaves = ['a', 'b', 'c', 'd'].map(leafHash);
  for (let i = 0; i < 4; i++) {
    const { rootHex, siblings } = buildTreeAndProof(leaves, i);
    const computed = computeMerkleRootFromProof(leaves[i], i, siblings, 4);
    assert.equal(computed, rootHex, `mismatch at index ${i}`);
  }
});

test('parseDuration: PT5M → 300', () => {
  assert.equal(parseDuration('PT5M'), 300);
});

test('parseDuration: PT1H30M → 5400', () => {
  assert.equal(parseDuration('PT1H30M'), 5400);
});

test('parseDuration: P1D → 86400', () => {
  assert.equal(parseDuration('P1D'), 86400);
});

test('parseDuration: malformed → null', () => {
  assert.equal(parseDuration('not-a-duration'), null);
  assert.equal(parseDuration(null), null);
});

test('verifyRekorAnchor: receipt without anchor_uri → undecidable', () => {
  const r = verifyRekorAnchor({
    receipt: { payload: {}, signature: {} },
  });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'no_anchor_uri_in_receipt');
  assert.equal(r.mode, 'undecidable');
});

test('verifyRekorAnchor: receipt with anchor_uri but no proof → undecidable', () => {
  const r = verifyRekorAnchor({
    receipt: {
      payload: { anchor_uri: 'rekor://example/1', issued_at: '2026-04-20T00:00:00Z' },
      signature: {},
    },
  });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'no_inclusion_proof_provided');
  assert.equal(r.mode, 'undecidable');
});

test('verifyRekorAnchor: expectedAnchorUri mismatch → undecidable', () => {
  const r = verifyRekorAnchor({
    receipt: { payload: { anchor_uri: 'rekor://a/1' }, signature: {} },
    expectedAnchorUri: 'rekor://b/1',
  });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'anchor_uri_mismatch');
});

test('verifyRekorAnchor: valid Merkle path for a real receipt', async () => {
  const { computeReceiptHash } = await import('../../src/engines/rekor.js');
  const receipt = {
    payload: {
      type: 'decision-receipt',
      action: 'Bash',
      anchor_uri: 'rekor://test/1',
      issued_at: '2026-04-20T00:00:00Z',
    },
    signature: { alg: 'EdDSA', kid: 'k', sig: 'deadbeef' },
  };
  const leafHex = computeReceiptHash(receipt);

  // Place the receipt as leaf 1 in a 2-leaf tree.
  const otherLeaf = leafHash('other');
  const { rootHex, siblings } = buildTreeAndProof([leafHex, otherLeaf], 0);

  const proof = { logID: 'test-log', treeSize: 2, logIndex: 0, rootHash: rootHex, hashes: siblings };
  const r = verifyRekorAnchor({
    receipt,
    proof: { ...proof, signedTreeHead: signedTreeHead(2, rootHex) },
    logTrustAnchors: { 'test-log': logKey },
  });

  assert.equal(r.valid, true, JSON.stringify(r));
  assert.equal(r.mode, 'proof');
  assert.equal(r.log_index, 0);
  assert.equal(r.root_hash, rootHex);

  // The same path with no signed tree head, or with no key pinned for the log, is not an anchor.
  const unsigned = verifyRekorAnchor({ receipt, proof, logTrustAnchors: { 'test-log': logKey } });
  assert.equal(unsigned.valid, false);
  assert.equal(unsigned.error, 'signed_tree_head_missing');
  assert.equal(unsigned.mode, 'undecidable');
  const unpinned = verifyRekorAnchor({ receipt, proof: { ...proof, signedTreeHead: signedTreeHead(2, rootHex) } });
  assert.equal(unpinned.error, 'no_log_trust_anchor');
  // A checkpoint the pinned key signed for another tree vouches for nothing here.
  const other = verifyRekorAnchor({ receipt, proof: { ...proof, signedTreeHead: signedTreeHead(3, rootHex) }, logTrustAnchors: { 'test-log': logKey } });
  assert.equal(other.error, 'signed_tree_head_mismatch');
});

test('computeReceiptHash: every member counts, at every depth', () => {
  const a = { payload: { tool_name: 'transfer', amount: 1, anchor_uri: 'rekor://x', issued_at: '2026-10-23T00:00:00Z' }, signature: { alg: 'EdDSA', kid: 'k', sig: 'aa' } };
  const b = { payload: { tool_name: 'delete_all', amount: 999999, anchor_uri: 'rekor://x', issued_at: '2026-10-23T00:00:00Z' }, signature: { alg: 'EdDSA', kid: 'other', sig: 'bb' } };
  assert.notEqual(computeReceiptHash(a), computeReceiptHash(b));
});

test('verifyRekorAnchor: a self-made one-leaf proof with no signed tree head is not an anchor', () => {
  const b = { payload: { tool_name: 'delete_all', amount: 999999, anchor_uri: 'rekor://x', issued_at: '2026-10-23T00:00:00Z' }, signature: { alg: 'EdDSA', kid: 'other', sig: 'bb' } };
  const r = verifyRekorAnchor({ receipt: b, proof: { logID: 'ff', treeSize: 1, logIndex: 0, hashes: [], rootHash: computeReceiptHash(b) } });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'signed_tree_head_missing');
});

test('verifyRekorAnchor: bogus sibling fails Merkle path', async () => {
  const { computeReceiptHash } = await import('../../src/engines/rekor.js');
  const receipt = {
    payload: {
      type: 'decision-receipt',
      action: 'Read',
      anchor_uri: 'rekor://test/2',
      issued_at: '2026-04-20T00:00:00Z',
    },
    signature: { alg: 'EdDSA', kid: 'k', sig: 'deadbeef' },
  };
  const leafHex = computeReceiptHash(receipt);

  const otherLeaf = leafHash('other');
  const { rootHex } = buildTreeAndProof([leafHex, otherLeaf], 0);

  const r = verifyRekorAnchor({
    receipt,
    proof: {
      logID: 'test-log',
      treeSize: 2,
      logIndex: 0,
      rootHash: rootHex,
      hashes: ['0'.repeat(64)],  // bogus sibling
    },
  });

  assert.equal(r.valid, false);
  assert.match(r.error, /merkle_path/);
});
