/**
 * `verify chain explore` through the CLI on a draft §6.7 chain: it walks to the root and exits 0, and a link refused
 * for its form exits as the receipt verifier would, 1 when malformed and 2 when it names another algorithm.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtempSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {canonicalize} from '../../src/util/canonical.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const digest = (value, algorithm = 'sha256') => createHash(algorithm).update(canonicalize(value)).digest('hex');
const receipt = (action, link) => ({
  payload: {type: 'protectmcp:decision', tool_name: action, decision: 'allow', issued_at: '2026-10-12T00:00:00Z', ...(link === undefined ? {} : {previousReceiptHash: link})},
  signature: {alg: 'EdDSA', kid: 'test:chain-explore', sig: '00'.repeat(64)},
});

// A root and a middle receipt linked by §6.7, and a tip whose link to the middle one is written by tipLink.
function explore(tipLink) {
  const dir = mkdtempSync(join(tmpdir(), 'acta-chain-explore-'));
  const root = receipt('records.read');
  const middle = receipt('records.share', `sha256:${digest(root)}`);
  writeFileSync(join(dir, '0001.json'), JSON.stringify(root));
  writeFileSync(join(dir, '0002.json'), JSON.stringify(middle));
  writeFileSync(join(dir, '0003.json'), JSON.stringify(receipt('records.delete', tipLink(middle))));
  const child = spawnSync(process.execPath, [cli, 'chain', 'explore', join(dir, '0003.json'), '--json'], {encoding: 'utf8', timeout: 20000});
  return {status: child.status, report: JSON.parse(child.stdout)};
}

test('cli: a §6.7 chain walks to its root (exit 0)', () => {
  const {status, report} = explore((m) => `sha256:${digest(m)}`);
  assert.equal(report.valid, true);
  assert.equal(report.depth, 3);
  assert.equal(report.links_broken, 0);
  assert.equal(status, 0);
});

test('cli: a malformed link exits 1 with malformed_chain_link', () => {
  const {status, report} = explore((m) => `sha256:${digest(m).toUpperCase()}`);
  assert.equal(report.valid, false);
  assert.equal(report.code, 'malformed_chain_link');
  assert.equal(status, 1);
});

test('cli: a link naming another algorithm exits 2 with unsupported_chain_hash_algorithm', () => {
  const {status, report} = explore((m) => `sha512:${digest(m, 'sha512')}`);
  assert.equal(report.valid, false);
  assert.equal(report.code, 'unsupported_chain_hash_algorithm');
  assert.equal(status, 2);
});
