/**
 * --audit-log: each entry's _chain_hash is sha256(previous entry's _chain_hash || the entry), as audit-log.js
 * defines it, so the log is append-only verifiable. Before, the CLI never passed the previous hash, so every entry was
 * hashed as if it were the first and the chain chained nothing: removing or reordering entries left every hash valid.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const cli = join(root, 'cli.js');
const sample = join(root, 'samples/sample-receipt.json');
const KEY = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
const entries = (file) => readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const chainHash = (prev, entry) => {
  const { _chain_hash, ...rest } = entry;
  return createHash('sha256').update(`${prev}${JSON.stringify(rest, Object.keys(rest).sort())}`).digest('hex');
};

test('cli --audit-log: each entry chains to the one before it', () => {
  const log = join(mkdtempSync(join(tmpdir(), 'acta-audit-log-')), 'audit.jsonl');
  for (let i = 0; i < 3; i++) assert.equal(run(sample, '--key', KEY, '--audit-log', log).status, 0);
  const [first, second, third] = entries(log);
  assert.equal(first._chain_hash, chainHash('', first), 'the first entry starts the chain');
  assert.equal(second._chain_hash, chainHash(first._chain_hash, second), 'the second chains to the first');
  assert.equal(third._chain_hash, chainHash(second._chain_hash, third), 'the third chains to the second');
});

test('cli --audit-log: an entry is not appended to a log whose last line it cannot chain to', () => {
  const log = join(mkdtempSync(join(tmpdir(), 'acta-audit-log-')), 'audit.jsonl');
  writeFileSync(log, '{"note":"not an entry"}\n');
  const r = run(sample, '--key', KEY, '--audit-log', log);
  assert.equal(r.status, 0, 'the verification itself is unaffected');
  assert.match(r.stderr, /failed to append audit log: the last entry carries no _chain_hash/);
  assert.equal(entries(log).length, 1);
});
