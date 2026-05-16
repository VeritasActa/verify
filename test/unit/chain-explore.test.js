/**
 * Unit tests for chain-explore engine.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import { exploreChain, renderChainTree, groupByTrace } from '../../src/engines/chain-explore.js';
import { canonicalize } from '../../src/util/canonical.js';

function receiptHash(env) {
  const bytes = canonicalize(env);
  return createHash('sha256').update(bytes).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function mkReceipt(action, previousReceiptHash) {
  return {
    payload: {
      type: 'decision-receipt',
      action,
      issuer_id: 'test-issuer',
      agent_id: 'test-agent',
      issued_at: '2026-04-20T00:00:00Z',
      ...(previousReceiptHash ? { previousReceiptHash } : {}),
    },
    signature: { alg: 'ed25519', kid: 'test-kid', sig: 'deadbeef' },
  };
}

function mkChain(dir, actions) {
  let prev = null;
  const paths = [];
  for (let i = 0; i < actions.length; i++) {
    const r = mkReceipt(actions[i], prev);
    const p = join(dir, `${String(i).padStart(2, '0')}-${actions[i]}.json`);
    writeFileSync(p, JSON.stringify(r));
    paths.push(p);
    prev = receiptHash(r);
  }
  return paths;
}

test('exploreChain: 3-receipt chain walks to root with no breaks', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const paths = mkChain(dir, ['root', 'middle', 'tip']);
  const tip = paths[paths.length - 1];

  const r = await exploreChain({ receiptPath: tip });
  assert.equal(r.valid, true);
  assert.equal(r.depth, 3);
  assert.equal(r.links_broken, 0);
  assert.equal(r.nodes.length, 3);
  assert.equal(r.nodes[0].action, 'tip');
  assert.equal(r.nodes[2].action, 'root');
  assert.equal(r.nodes[2].previousHash, null);
  assert.equal(r.warnings.length, 0);
});

test('exploreChain: single root receipt', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const paths = mkChain(dir, ['solo']);
  const r = await exploreChain({ receiptPath: paths[0] });
  assert.equal(r.valid, true);
  assert.equal(r.depth, 1);
  assert.equal(r.nodes[0].previousHash, null);
});

test('exploreChain: tampered middle receipt invalidates chain', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const paths = mkChain(dir, ['root', 'middle', 'tip']);
  // Tamper with the middle receipt so its hash changes.
  const tampered = JSON.parse(
    (await import('node:fs')).readFileSync(paths[1], 'utf-8')
  );
  tampered.payload.action = 'tampered';
  writeFileSync(paths[1], JSON.stringify(tampered));

  const r = await exploreChain({ receiptPath: paths[2] });
  assert.equal(r.valid, false);
  assert.equal(r.links_broken, 1);
  assert.equal(r.nodes[0].link_valid, false);
  assert.ok(r.warnings.length > 0);
});

test('exploreChain: missing ancestor reports broken link', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  // Write only the tip; its previousReceiptHash points to nothing in the dir.
  const orphan = mkReceipt('orphan-tip', 'Zm9v'.repeat(11).slice(0, 43));
  const p = join(dir, 'tip.json');
  writeFileSync(p, JSON.stringify(orphan));

  const r = await exploreChain({ receiptPath: p });
  assert.equal(r.valid, false);
  assert.equal(r.links_broken, 1);
  assert.equal(r.depth, 1);
});

test('exploreChain: unreadable starting receipt', async () => {
  const r = await exploreChain({ receiptPath: '/does/not/exist/tip.json' });
  assert.equal(r.valid, false);
  assert.match(r.error, /cannot_read_starting_receipt/);
});

test('exploreChain: maxDepth truncates long chains', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const actions = Array.from({ length: 6 }, (_, i) => `step-${i}`);
  const paths = mkChain(dir, actions);
  const r = await exploreChain({ receiptPath: paths[paths.length - 1], maxDepth: 3 });
  assert.equal(r.depth, 3);
  assert.ok(r.warnings.some((w) => /maxDepth/.test(w)));
});

test('exploreChain: searchDir override locates ancestors elsewhere', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const paths = mkChain(dir, ['a', 'b']);
  // Move the tip to a different directory and pass searchDir for the ancestor.
  const elsewhere = mkdtempSync(join(tmpdir(), 'other-'));
  const tipContent = (await import('node:fs')).readFileSync(paths[1], 'utf-8');
  const tipElsewhere = join(elsewhere, 'tip.json');
  writeFileSync(tipElsewhere, tipContent);

  const r = await exploreChain({
    receiptPath: tipElsewhere,
    searchDir: dir,
  });
  assert.equal(r.valid, true);
  assert.equal(r.depth, 2);
});

test('renderChainTree: human tree contains tip arrow and ascend glyph', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const paths = mkChain(dir, ['root', 'tip']);
  const r = await exploreChain({ receiptPath: paths[1] });
  const out = renderChainTree(r);
  assert.match(out, /Chain: depth=2/);
  assert.match(out, /▶/);
  assert.match(out, /↑/);
});

test('renderChainTree: failed chain renders error', () => {
  const out = renderChainTree({
    valid: false,
    depth: 0,
    links_broken: 0,
    nodes: [],
    warnings: [],
    error: 'cannot_read_starting_receipt',
  });
  assert.match(out, /Chain explore failed/);
});

test('exploreChain: surfaces trace_id and parent_receipt_id when present', async () => {
  const { createHash } = await import('node:crypto');
  const { canonicalize } = await import('../../src/util/canonical.js');
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const root = mkReceipt('root', null);
  root.payload.trace_id = 'trace-abc';
  const rootPath = join(dir, '01-root.json');
  writeFileSync(rootPath, JSON.stringify(root));
  const rootHash = createHash('sha256')
    .update(canonicalize(root))
    .digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const tip = mkReceipt('tip', rootHash);
  tip.payload.trace_id = 'trace-abc';
  tip.payload.parent_receipt_id = rootHash;
  const tipPath = join(dir, '02-tip.json');
  writeFileSync(tipPath, JSON.stringify(tip));

  const r = await exploreChain({ receiptPath: tipPath });
  assert.equal(r.valid, true);
  assert.equal(r.nodes[0].trace_id, 'trace-abc');
  assert.equal(r.nodes[1].trace_id, 'trace-abc');
  assert.equal(r.nodes[0].parent_receipt_id, rootHash);
});

test('groupByTrace: buckets nodes by trace_id', () => {
  const result = {
    nodes: [
      { trace_id: 'T1', action: 'a' },
      { trace_id: 'T2', action: 'b' },
      { trace_id: 'T1', action: 'c' },
      { trace_id: null, action: 'd' },
    ],
  };
  const g = groupByTrace(result);
  assert.equal(g['T1'].length, 2);
  assert.equal(g['T2'].length, 1);
  assert.equal(g['(no-trace)'].length, 1);
});
