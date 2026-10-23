/**
 * The formats that carry their own key (Gate tuples and evidence bundles, macro snapshots and track records, governed
 * receipts, proof packs, trusted context packs, repository evidence, and the standard files and run manifests): a
 * result that rests only on a key the file carries is undecidable (embedded_key_rejected, exit 2), by default and under
 * --strict (draft §9.5). --allow-carried-key accepts it (exit 0), and the output says the signature proves nothing about
 * who signed; --strict refuses it even then. Before, these formats exited 0 on the key they carry, under --strict too,
 * so a Gate decision signed by any fresh key passed.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { sortKeysDeep } from '../../src/util/canonical.js';

const root = fileURLToPath(new URL('../../', import.meta.url));
const cli = join(root, 'cli.js');
const dir = mkdtempSync(join(tmpdir(), 'acta-strict-carried-'));
const write = (name, value) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(value)); return p; };
const read = (file) => JSON.parse(readFileSync(join(root, file), 'utf8'));
const run = (file, ...args) => spawnSync(process.execPath, [cli, file, ...args, '--json'], { encoding: 'utf8', timeout: 30000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
const json = (file, ...args) => { const r = run(file, ...args); return { status: r.status, report: JSON.parse(r.stdout) }; };

// A Gate-shaped tuple: Ed25519 over the SHA-256 of the sorted-key JSON of the payload.
const tuple = (payload, secret) => {
  const digest = sha256(utf8ToBytes(JSON.stringify(sortKeysDeep(payload))));
  return { payload, digest: bytesToHex(digest), signature: bytesToHex(ed25519.sign(digest, secret)), verification_key: bytesToHex(ed25519.getPublicKey(secret)) };
};

const contextPack = tuple({
  schema: 'scopeblind.trusted_context_pack.v1', workspace_id: 'w', source_id: 'tcb-abc123def456-0', source_type: 'book_positions',
  source_format: 'csv', source_lineage: 'upload', file_name: 'positions.csv', file_hash: 'a'.repeat(64), parser_version: 'tcb/1.0.0',
  parsed_artifacts: { positions: [{ symbol: 'ESH6', market_value: 12500000, sector: 'index', asset_class: 'futures' }] },
  freshness: { as_of: '2026-06-16T00:00:00.000Z', ingested_at: '2026-06-16T12:00:00Z', max_age_days: 3, stale: false },
  confidence: 0.9, warnings: [], gate_status: 'usable', summary: { positions: 1 }, notice: 'attests the parse, not the provenance',
}, new Uint8Array(32).fill(0x31));

const coding = read('test/fixtures/repository-coding/published.json');
const cases = [
  ['a Gate receipt tuple', join(root, 'samples/sample-gate-tuple.json'), read('samples/sample-gate-tuple.json').verification_key],
  ['a macro snapshot', join(root, 'samples/macro/market-state.json'), read('samples/macro/market-state.json').verification_key],
  ['a Gate evidence bundle', join(root, 'samples/sample-gate-bundle.json'), read('samples/sample-gate-bundle.json').gate_verification_key],
  ['a macro track record', join(root, 'samples/macro/track-record-bundle.json'), read('samples/macro/track-record-bundle.json').model_verification_key],
  ['a governed receipt', join(root, 'samples/sample-restraint-receipt.json'), read('samples/sample-restraint-receipt.json').verification_key],
  ['a proof pack', join(root, 'samples/legate-proof-pack.json'), read('samples/legate-proof-pack.json').verification_key ?? read('samples/legate-proof-pack.json').runtime.verification_key],
  ['a trusted context pack', write('context-pack.json', contextPack), contextPack.verification_key],
  ['repository evidence', join(root, 'test/fixtures/repository-coding/published.json'), coding.job.payload.workspace.payload.workspace.payload.authority_key],
  ['a proof request', join(root, 'test/fixtures/legate/proof-request.json'), read('test/fixtures/legate/proof-request.json').recipient.verification_key],
  ['an admission decision', join(root, 'test/fixtures/legate/admission-decision.json'), read('test/fixtures/legate/admission-decision.json').recipient.verification_key],
  ['an action assurance bundle', join(root, 'test/fixtures/legate/action-bundle.json'), read('test/fixtures/legate/action-bundle.json').request.issuer.verification_key],
  ['a run manifest', join(root, 'test/fixtures/legate/run-manifest.json'), read('test/fixtures/legate/run-manifest.json').signer.verification_key],
];

test('cli: a result that rests only on the key the file carries is undecidable (exit 2) by default and under --strict, for every such format', () => {
  for (const [label, file, key] of cases) {
    for (const flags of [[], ['--strict'], ['--strict', '--allow-carried-key']]) {
      const refused = json(file, ...flags);
      assert.equal(refused.status, 2, `${label} ${flags.join(' ')}: ${JSON.stringify(refused.report).slice(0, 400)}`);
      assert.equal(refused.report.valid, false, label);
      assert.equal(refused.report.error, 'embedded_key_rejected', label);
      assert.equal(refused.report.carriedKeyOnly, true, label);
      assert.match(refused.report.detail, /checked only against a key it carries/, label);
    }
    // --allow-carried-key accepts it, and says what it rests on.
    const allowed = json(file, '--allow-carried-key');
    assert.equal(allowed.status, 0, `${label} --allow-carried-key: ${JSON.stringify(allowed.report).slice(0, 400)}`);
    assert.equal(allowed.report.carriedKeyOnly, true, label);
    assert.match(allowed.report.warning, /Checked only against the key the file carries \(--allow-carried-key\): .*proves nothing about who signed it/, label);
    // A key from outside the file is not a carried key: valid by default and under --strict.
    for (const flags of [[], ['--strict']]) {
      const pinned = json(file, ...flags, '--key', key);
      assert.equal(pinned.status, 0, `${label} --key ${flags.join(' ')}`);
      assert.equal(pinned.report.carriedKeyOnly, undefined, label);
    }
  }
});

test('cli --allow-carried-key: the terminal says plainly that the signature proves nothing about who signed', () => {
  for (const [label, file] of cases.slice(0, 3)) {
    const r = spawnSync(process.execPath, [cli, file, '--allow-carried-key'], { encoding: 'utf8', timeout: 30000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
    assert.equal(r.status, 0, label);
    assert.match(r.stdout, /^\n! Checked only against the key the file carries \(--allow-carried-key\): the signature shows the file matches that key, and proves nothing about who signed it\./, label);
  }
});

test('cli --strict: the report\'s forged Gate decision, signed by a fresh key, is undecidable, and invalid under the real key', () => {
  const forged = write('gate-forged.json', tuple({
    schema: 'scopeblind.gate.decision/2', proposal_id: 'prop-forged-1', proposal: { symbol: 'AAPL', side: 'buy', qty: 1000000 },
    decision: 'ALLOW', mandate_digest: 'a'.repeat(64), book_digest: 'b'.repeat(64), nav: 100000000, evaluated_at: '2026-10-23T00:00:00Z',
  }, new Uint8Array(32).fill(0x66)));
  assert.equal(json(forged).status, 2);
  assert.equal(json(forged, '--strict').status, 2);
  assert.equal(json(forged, '--allow-carried-key').report.carriedKeyOnly, true);
  const victim = bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(0x67)));
  const pinned = json(forged, '--key', victim);
  assert.equal(pinned.status, 1);
  assert.equal(pinned.report.error, 'key_mismatch');
});

test('cli --strict: a run manifest whose harness key the standard accepts, under a pinned maintainer key, rests on that pin', () => {
  const f = (name) => join(root, 'test/fixtures/legate', name);
  const companions = ['--standard', f('run-standard.json'), '--receipts', f('run-receipts.jsonl'), '--calls', f('run-calls.jsonl'), '--regrade', f('run-regrade.json')];
  const pinned = json(f('run-manifest.json'), ...companions, '--maintainer-key', read('test/fixtures/legate/run-standard.json').recipient.verification_key, '--strict');
  assert.equal(pinned.status, 0, JSON.stringify(pinned.report.checks?.filter((c) => !c.ok)));
  assert.equal(pinned.report.binding, 'bound');
  const unpinned = json(f('run-manifest.json'), ...companions, '--strict');
  assert.equal(unpinned.status, 2, JSON.stringify(unpinned.report).slice(0, 400));
  assert.equal(unpinned.report.error, 'embedded_key_rejected');
});
