/**
 * Unit tests for chain-explore engine.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import { exploreChain, renderChainTree, groupByTrace, chainLinkOf } from '../../src/engines/chain-explore.js';
import { canonicalize } from '../../src/util/canonical.js';

// Draft §6.7, computed here rather than by the engine: "sha256:" and the lowercase hex SHA-256 of the JCS of the
// whole receipt, signature included.
function receiptHash(env) {
  return 'sha256:' + createHash('sha256').update(canonicalize(env)).digest('hex');
}

function mkReceipt(action, previousReceiptHash, extra = {}) {
  return {
    payload: {
      type: 'decision-receipt',
      action,
      issuer_id: 'test-issuer',
      agent_id: 'test-agent',
      issued_at: '2026-04-20T00:00:00Z',
      ...extra,
      ...(previousReceiptHash !== null && previousReceiptHash !== undefined ? { previousReceiptHash } : {}),
    },
    signature: { alg: 'ed25519', kid: 'test-kid', sig: 'deadbeef' },
  };
}

// link(r) is the previousReceiptHash the next receipt carries for r; the default is the §6.7 value.
function mkChain(dir, actions, link = receiptHash, extra = {}) {
  let prev = null;
  const paths = [];
  for (let i = 0; i < actions.length; i++) {
    const r = mkReceipt(actions[i], prev, extra);
    const p = join(dir, `${String(i).padStart(2, '0')}-${actions[i]}.json`);
    writeFileSync(p, JSON.stringify(r));
    paths.push(p);
    prev = link(r);
  }
  return paths;
}

// A genesis receipt on disk, and a tip whose link names it in the given form.
function tipLinkingGenesis(link) {
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const genesis = mkReceipt('root', null);
  writeFileSync(join(dir, '00-root.json'), JSON.stringify(genesis));
  const p = join(dir, '01-tip.json');
  writeFileSync(p, JSON.stringify(mkReceipt('tip', link(genesis))));
  return p;
}

const digestOf = (env, algorithm = 'sha256', encoding = 'hex') =>
  createHash(algorithm).update(canonicalize(env)).digest(encoding);

test('exploreChain: 3-receipt chain walks to root with no breaks', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const paths = mkChain(dir, ['root', 'middle', 'tip']);
  const tip = paths[paths.length - 1];

  const r = await exploreChain({ receiptPath: tip });
  assert.equal(r.valid, true);
  assert.equal(r.depth, 3);
  assert.equal(r.links_broken, 0);
  assert.equal(r.legacy_links, 0);
  assert.equal(r.nodes.length, 3);
  assert.equal(r.nodes[0].action, 'tip');
  assert.equal(r.nodes[2].action, 'root');
  assert.equal(r.nodes[2].previousHash, null);
  assert.equal(r.warnings.length, 0);
});

test('exploreChain: every node carries its §6.7 value, and each link names the next node (draft §6.7)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const paths = mkChain(dir, ['root', 'middle', 'tip']);
  const r = await exploreChain({ receiptPath: paths[2] });
  assert.equal(r.valid, true);
  for (let i = 0; i < r.nodes.length; i++) {
    const onDisk = JSON.parse(readFileSync(r.nodes[i].path, 'utf-8'));
    assert.equal(r.nodes[i].hash, receiptHash(onDisk));
    assert.match(r.nodes[i].hash, /^sha256:[0-9a-f]{64}$/);
    if (i < r.nodes.length - 1) {
      assert.equal(r.nodes[i].previousHash, r.nodes[i + 1].hash);
      assert.equal(r.nodes[i].link_form, 'sha256');
    }
  }
  assert.equal(r.nodes[2].link_form, null);
});

test('chainLinkOf: the §6.7 value of a receipt', () => {
  const r = mkReceipt('solo', null);
  assert.equal(chainLinkOf(r), receiptHash(r));
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
  const tampered = JSON.parse(readFileSync(paths[1], 'utf-8'));
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
  const orphan = mkReceipt('orphan-tip', `sha256:${'ab'.repeat(32)}`);
  const p = join(dir, 'tip.json');
  writeFileSync(p, JSON.stringify(orphan));

  const r = await exploreChain({ receiptPath: p });
  assert.equal(r.valid, false);
  assert.equal(r.links_broken, 1);
  assert.equal(r.depth, 1);
  assert.equal(r.code, undefined);
  assert.ok(r.warnings.some((w) => /not found in searchDir/.test(w)));
});

test('exploreChain: the bare digest of earlier revisions resolves, and is named (draft §6.7)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const paths = mkChain(dir, ['root', 'tip'], (r) => digestOf(r));
  const r = await exploreChain({ receiptPath: paths[1] });
  assert.equal(r.valid, true);
  assert.equal(r.depth, 2);
  assert.equal(r.nodes[0].link_form, 'legacy-bare-hex');
});

// The ancestor cites -03, -02, -01, or no revision at all: spec is optional, so it decides nothing about the link.
const CITES = [
  ['-03', { spec: 'draft-farley-acta-signed-receipts-03' }],
  ['-02', { spec: 'draft-farley-acta-signed-receipts-02' }],
  ['-01', { spec: 'draft-farley-acta-signed-receipts-01' }],
  ['no spec member', {}],
];
const PAYLOAD_LINKS = [
  ['prefixed', (r) => `sha256:${digestOf(r.payload)}`],
  ['bare hex', (r) => digestOf(r.payload)],
];

test('exploreChain: a payload-only link is refused with chain_break whatever the ancestor cites (draft §6.7)', async () => {
  for (const [cites, extra] of CITES) {
    for (const [form, payloadLink] of PAYLOAD_LINKS) {
      const dir = mkdtempSync(join(tmpdir(), 'chain-'));
      const paths = mkChain(dir, ['root', 'tip'], payloadLink, extra);
      const r = await exploreChain({ receiptPath: paths[1] });
      const name = `${cites}, ${form}`;
      assert.equal(r.valid, false, name);
      assert.equal(r.links_broken, 1, name);
      assert.equal(r.legacy_links, 0, name);
      assert.equal(r.code, 'chain_break', name);
      assert.equal(r.depth, 1, name);
      assert.equal(r.nodes[0].link_valid, false, name);
      assert.equal(r.nodes[0].link_error, 'chain_break', name);
      assert.ok(r.warnings.some((w) => w.includes(paths[0]) && /payload alone/.test(w) && /--allow-payload-only-links/.test(w)), name);
    }
  }
});

test('exploreChain: allowPayloadOnlyLinks reads a payload-only link as a legacy link, counted and warned, whatever the ancestor cites', async () => {
  for (const [cites, extra] of CITES) {
    for (const [form, payloadLink] of PAYLOAD_LINKS) {
      const dir = mkdtempSync(join(tmpdir(), 'chain-'));
      const paths = mkChain(dir, ['root', 'middle', 'tip'], payloadLink, extra);
      const r = await exploreChain({ receiptPath: paths[2], allowPayloadOnlyLinks: true });
      const name = `${cites}, ${form}`;
      assert.equal(r.valid, true, name);
      assert.equal(r.depth, 3, name);
      assert.equal(r.legacy_links, 2, name);
      assert.equal(r.code, undefined, name);
      assert.equal(r.nodes[0].link_form, 'legacy-payload', name);
      assert.equal(r.nodes[1].link_form, 'legacy-payload', name);
      assert.equal(r.warnings.filter((w) => /read as a legacy link because --allow-payload-only-links was given/.test(w)).length, 2, name);
      assert.match(renderChainTree(r), /legacy_links=2/, name);
    }
  }
});

test('exploreChain: allowPayloadOnlyLinks leaves whole-receipt links, bare hex and missing ancestors as they were', async () => {
  for (const link of [receiptHash, (r) => digestOf(r)]) {
    const dir = mkdtempSync(join(tmpdir(), 'chain-'));
    const paths = mkChain(dir, ['root', 'tip'], link);
    const r = await exploreChain({ receiptPath: paths[1], allowPayloadOnlyLinks: true });
    assert.equal(r.valid, true);
    assert.equal(r.legacy_links, 0);
    assert.deepEqual(r.warnings, []);
  }
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const p = join(dir, 'tip.json');
  writeFileSync(p, JSON.stringify(mkReceipt('orphan-tip', `sha256:${'ab'.repeat(32)}`)));
  const orphan = await exploreChain({ receiptPath: p, allowPayloadOnlyLinks: true });
  assert.equal(orphan.valid, false);
  assert.equal(orphan.legacy_links, 0);
  assert.equal(orphan.code, undefined);
  assert.ok(orphan.warnings.some((w) => /not found in searchDir/.test(w)));
});

test('exploreChain: a malformed link is refused with the receipt verifier\'s code, though its ancestor is present (draft §6.7)', async () => {
  const forms = {
    'not a digest': () => 'sha256:not-a-digest',
    'uppercase hex': (g) => `sha256:${digestOf(g).toUpperCase()}`,
    // The unprefixed base64url digest that chain explore itself looked ancestors up by before 0.10.23.
    'unprefixed base64url': (g) => digestOf(g, 'sha256', 'base64url'),
    'empty string': () => '',
    'not a string': () => 42,
  };
  for (const [name, link] of Object.entries(forms)) {
    const r = await exploreChain({ receiptPath: tipLinkingGenesis(link) });
    assert.equal(r.valid, false, name);
    assert.equal(r.code, 'malformed_chain_link', name);
    assert.equal(r.nodes[0].link_error, 'malformed_chain_link', name);
    assert.equal(r.nodes[0].link_valid, false, name);
    assert.equal(r.depth, 1, name);
  }
});

test('exploreChain: a link naming another algorithm is refused rather than read as SHA-256 (draft §6.7)', async () => {
  for (const link of [(g) => `sha512:${digestOf(g, 'sha512')}`, (g) => `sha3-256:${digestOf(g, 'sha3-256')}`]) {
    const r = await exploreChain({ receiptPath: tipLinkingGenesis(link) });
    assert.equal(r.valid, false);
    assert.equal(r.code, 'unsupported_chain_hash_algorithm');
    assert.equal(r.nodes[0].link_error, 'unsupported_chain_hash_algorithm');
  }
});

test('exploreChain: a null link is a root, named with a §2.2 warning', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const root = mkReceipt('root', null);
  root.payload.previousReceiptHash = null;
  writeFileSync(join(dir, '00-root.json'), JSON.stringify(root));
  const tipPath = join(dir, '01-tip.json');
  writeFileSync(tipPath, JSON.stringify(mkReceipt('tip', receiptHash(root))));

  const r = await exploreChain({ receiptPath: tipPath });
  assert.equal(r.valid, true);
  assert.equal(r.depth, 2);
  assert.ok(r.warnings.some((w) => /§2\.2/.test(w)));
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
  const tipContent = readFileSync(paths[1], 'utf-8');
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
  assert.ok(out.includes(`${r.nodes[0].hash.slice(7, 19)}...`));
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
  const dir = mkdtempSync(join(tmpdir(), 'chain-'));
  const root = mkReceipt('root', null);
  root.payload.trace_id = 'trace-abc';
  const rootPath = join(dir, '01-root.json');
  writeFileSync(rootPath, JSON.stringify(root));
  const rootHash = receiptHash(root);

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
