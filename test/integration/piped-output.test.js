/**
 * A result larger than a pipe holds reaches the reader whole, with the exit status of the outcome. Up to 0.11.0 the CLI
 * ended each run with process.exit(), which ends the process at once, while Node can still be writing stdout to a pipe
 * or a socket: whatever the reader had not yet taken was lost. `verify --replay-chain receipts.jsonl --key <hex> --json
 * | jq` read the first 64 KiB of the report, and the exit status was still 0. Each run here sends several times that
 * through stdout, reads all of it and checks the exit status, for each outcome.
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

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
// A key made for this test, not any issuer's.
const secret = new Uint8Array(32).fill(64);
const key = bytesToHex(ed25519.getPublicKey(secret));
const KID = 'test:piped-output';
const sign = (payload) => ({ payload, signature: { alg: 'EdDSA', kid: KID, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), secret)) } });
const link = (receipt) => `sha256:${createHash('sha256').update(canonicalize(receipt)).digest('hex')}`;

// One chain, long enough that each report below is several times the 64 KiB a pipe holds.
const COUNT = 320;
const FLOOR = 4 * 64 * 1024;
const receipts = [];
for (let i = 0; i < COUNT; i++) {
  const payload = {
    type: 'protectmcp:decision',
    spec: 'draft-farley-acta-signed-receipts-03',
    tool_name: `records.read.${i}`,
    decision: 'allow',
    issued_at: new Date(Date.UTC(2026, 9, 25, 0, 0, i)).toISOString(),
    issuer_id: KID,
  };
  if (i > 0) payload.previousReceiptHash = link(receipts[i - 1]);
  receipts.push(sign(payload));
}
const dir = mkdtempSync(join(tmpdir(), 'verify-piped-output-'));
const file = (name, text) => { const path = join(dir, name); writeFileSync(path, text); return path; };
const jsonl = (list) => list.map((r) => JSON.stringify(r)).join('\n') + '\n';
const chain = file('receipts.jsonl', jsonl(receipts));
// The last receipt's decision changed after it was signed: that line fails, and so does the chain (exit 1).
const last = receipts[COUNT - 1];
const tampered = file('tampered.jsonl', jsonl([...receipts.slice(0, -1), { ...last, payload: { ...last.payload, decision: 'deny' } }]));
const bundle = file('bundle.json', JSON.stringify({ format: 'scopeblind:audit-bundle:v1', receipts }));

const options = { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 120000, env: { ...process.env, NO_COLOR: '1', CI: '1' } };

// The CLI as Node starts it with stdout piped back to the caller (spawn, execFile), which reads it as it arrives.
function spawned(args) {
  const run = spawnSync(process.execPath, [cli, ...args], options);
  if (run.error) throw run.error;
  return { status: run.status, stdout: run.stdout, stderr: run.stderr };
}

// The CLI in a shell pipeline, `verify ... | cat`, as jq or wc would read it: its exit status comes back on fd 3.
function piped(args) {
  const run = spawnSync('sh', ['-c', '{ "$0" "$@"; echo "$?" >&3; } | cat', process.execPath, cli, ...args], { ...options, stdio: ['ignore', 'pipe', 'pipe', 'pipe'] });
  if (run.error) throw run.error;
  return { status: Number(run.output[3]), stdout: run.stdout, stderr: run.stderr };
}
const noShell = process.platform === 'win32' && 'needs a POSIX shell';

/** The whole report, parsed: it fails, naming how much arrived, when stdout ended early. */
function whole(run, label) {
  const bytes = Buffer.byteLength(run.stdout);
  let report;
  try {
    report = JSON.parse(run.stdout);
  } catch (e) {
    assert.fail(`${label}: stdout ended after ${bytes} bytes and is not one whole JSON document (${e.message}); exit ${run.status}`);
  }
  assert.ok(bytes > FLOOR, `${label}: a report of ${bytes} bytes is too small to test this`);
  return report;
}

test('a valid chain: the whole report arrives through a socket from Node, with exit 0', () => {
  const run = spawned(['--replay-chain', chain, '--key', key, '--json']);
  const report = whole(run, 'replay, spawned');
  assert.equal(run.status, 0, run.stderr);
  assert.equal(report.outcome, 'valid');
  assert.equal(report.total, COUNT);
  assert.equal(report.verified, COUNT);
  assert.equal(report.receipts.length, COUNT);
  assert.equal(run.stderr, '');
});

test('a valid chain: the whole report arrives through a shell pipe, with exit 0', { skip: noShell }, () => {
  const run = piped(['--replay-chain', chain, '--key', key, '--json']);
  const report = whole(run, 'replay, piped');
  assert.equal(run.status, 0, run.stderr);
  assert.equal(report.outcome, 'valid');
  assert.equal(report.verified, COUNT);
  assert.equal(report.receipts.length, COUNT);
  assert.equal(run.stderr, '');
});

test('a chain with one changed receipt: the whole report arrives through a pipe, with exit 1', { skip: noShell }, () => {
  const run = piped(['--replay-chain', tampered, '--key', key, '--json']);
  const report = whole(run, 'replay, one receipt changed');
  assert.equal(run.status, 1, run.stderr);
  assert.equal(report.outcome, 'invalid');
  assert.equal(report.failed, 1);
  assert.equal(report.verified, COUNT - 1);
  assert.equal(report.receipts[COUNT - 1].error, 'invalid_signature');
});

test('a chain checked with no key: the whole report arrives through a pipe, with exit 2', { skip: noShell }, () => {
  const run = piped(['--replay-chain', chain, '--json']);
  const report = whole(run, 'replay, no key');
  assert.equal(run.status, 2, run.stderr);
  assert.equal(report.outcome, 'undecidable');
  assert.equal(report.undecidable, COUNT);
  assert.equal(report.receipts.length, COUNT);
});

test('an audit bundle: the whole result arrives through a pipe, with exit 0', { skip: noShell }, () => {
  const run = piped([bundle, '--bundle', '--key', key, '--json']);
  const report = whole(run, 'bundle, piped');
  assert.equal(run.status, 0, run.stderr);
  assert.equal(report.valid, true);
  assert.equal(report.total, COUNT);
  assert.equal(report.passed, COUNT);
});

test('a replay audit report: the whole HTML page arrives through a pipe, with exit 1 for a changed receipt', { skip: noShell }, () => {
  const run = piped(['--replay-chain', tampered, '--key', key, '--audit-report']);
  const bytes = Buffer.byteLength(run.stdout);
  assert.match(run.stdout.trimEnd(), /<\/html>$/i, `the page ended after ${bytes} bytes; exit ${run.status}`);
  assert.ok(bytes > FLOOR, `a page of ${bytes} bytes is too small to test this`);
  assert.equal(run.status, 1, run.stderr);
});
