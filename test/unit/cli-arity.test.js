import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const cli = join(here, '..', '..', 'cli.js');
const sample = join(here, '..', '..', 'samples', 'sample-receipt.json');
const ARITY = /expected one <file\.json>/;

test('two positionals are an error, not a silent drop', () => {
  const r = spawnSync(process.execPath, [cli, sample, sample], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /expected one <file\.json>, got 2/);
  assert.match(r.stderr, /silently discarded/);
});

test('one positional is not rejected by the arity guard', () => {
  const r = spawnSync(process.execPath, [cli, sample], { encoding: 'utf8' });
  assert.doesNotMatch(r.stderr, ARITY);
});

test('no positional still reaches the self-test path (exit 0)', () => {
  const r = spawnSync(process.execPath, [cli, '--self-test'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
});
