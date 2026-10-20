/**
 * Draft-03 §6.7 through the CLI: --replay-chain and `verify chain explore` refuse a link over the previous receipt's
 * payload alone (chain_break, exit 1) whatever that receipt cites, --allow-payload-only-links reads one as a legacy link
 * that is counted and shown, and --strict switches the flag off on both paths. Also: replay names each chain a file
 * holds, and --strict reaches the replay path for the other compatibility flags too.
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
import { canonicalize, legacyCanonicalize } from '../../src/util/canonical.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const secret = new Uint8Array(32).fill(37);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const sha = (value) => createHash('sha256').update(canonicalize(value)).digest('hex');
const envelope = (payload, encode = canonicalize) => ({ payload, signature: { alg: 'EdDSA', kid: 'test:payload-only', sig: bytesToHex(ed25519.sign(utf8ToBytes(encode(payload)), secret)) } });
const fields = (n, extra = {}) => ({ type: 'protectmcp:decision', tool_name: `records.${n}`, decision: 'allow', issued_at: `2026-10-19T00:00:0${n}Z`, ...extra });
const whole = (r) => `sha256:${sha(r)}`;
const payloadOnly = (r) => `sha256:${sha(r.payload)}`;

// A genesis citing `cites` and a second receipt linked to it by `link`, as a JSONL file and as a directory.
function pair(link, cites = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'acta-payload-only-'));
  const first = envelope(fields(1, cites));
  const second = envelope(fields(2, { spec: 'draft-farley-acta-signed-receipts-03', previousReceiptHash: link(first) }));
  writeFileSync(join(dir, 'receipts.jsonl'), `${JSON.stringify(first)}\n${JSON.stringify(second)}\n`);
  writeFileSync(join(dir, '01.json'), JSON.stringify(first));
  writeFileSync(join(dir, '02.json'), JSON.stringify(second));
  return dir;
}
const run = (args, input) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 20000, input, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
const replay = (dir, ...extra) => run(['--replay-chain', join(dir, 'receipts.jsonl'), '--key', publicKey, ...extra]);
const explore = (dir, ...extra) => run(['chain', 'explore', join(dir, '02.json'), ...extra]);

test('cli: a whole-receipt link replays and walks (exit 0), with or without the flag', () => {
  for (const extra of [[], ['--allow-payload-only-links']]) {
    const dir = pair(whole, { spec: 'draft-farley-acta-signed-receipts-03' });
    const r = replay(dir, '--json', ...extra);
    assert.equal(r.status, 0, r.stdout);
    assert.equal(JSON.parse(r.stdout).legacyLinks, 0);
    const e = explore(dir, '--json', ...extra);
    assert.equal(e.status, 0, e.stdout);
    assert.equal(JSON.parse(e.stdout).legacy_links, 0);
  }
});

test('cli: a payload-only link is a chain break on both paths (exit 1), with or without a spec on the predecessor', () => {
  for (const cites of [{ spec: 'draft-farley-acta-signed-receipts-03' }, { spec: 'draft-farley-acta-signed-receipts-02' }, {}]) {
    const dir = pair(payloadOnly, cites);
    const r = replay(dir, '--json');
    assert.equal(r.status, 1, JSON.stringify(cites));
    const report = JSON.parse(r.stdout);
    assert.equal(report.valid, false);
    assert.equal(report.chainBreaks, 1);
    assert.equal(report.legacyLinks, 0);
    assert.match(report.errors[0], /chain_break.*payload alone.*--allow-payload-only-links/);
    const e = explore(dir, '--json');
    assert.equal(e.status, 1, JSON.stringify(cites));
    const walked = JSON.parse(e.stdout);
    assert.equal(walked.code, 'chain_break');
    assert.equal(walked.links_broken, 1);
  }
});

test('cli: the bare hex of a whole receipt is still read; the bare hex of a payload alone is refused', () => {
  const bareWhole = pair((r) => whole(r).slice(7));
  assert.equal(replay(bareWhole).status, 0);
  assert.equal(explore(bareWhole).status, 0);
  const barePayload = pair((r) => payloadOnly(r).slice(7));
  assert.equal(replay(barePayload).status, 1);
  assert.equal(explore(barePayload).status, 1);
});

test('cli: --allow-payload-only-links reads it as a legacy link, counted and shown in the terminal and in JSON', () => {
  const dir = pair(payloadOnly, { spec: 'draft-farley-acta-signed-receipts-03' });
  const json = replay(dir, '--allow-payload-only-links', '--json');
  assert.equal(json.status, 0, json.stdout);
  const report = JSON.parse(json.stdout);
  assert.equal(report.legacyLinks, 1);
  // §6.7.1 of the -04 editor's copy (VeritasActa/drafts) says a verifier must not accept one, so reading it is marked as
  // a compatibility mode (0.10.26).
  assert.equal(report.conformant, false);
  assert.match(report.warnings[0], /^Line 2: payload-only link to line 1, read as a legacy link because --allow-payload-only-links was given: read under a compatibility mode, not conformant to draft §6\.7/);
  const text = replay(dir, '--allow-payload-only-links');
  assert.equal(text.status, 0);
  assert.match(text.stdout, /Legacy links: 1 \(payload-only, read because --allow-payload-only-links was given: read under a compatibility mode, not conformant to draft §6\.7\)/);
  assert.match(text.stdout, /Warnings:\n\s+• Line 2: payload-only link to line 1/);
  const walked = explore(dir, '--allow-payload-only-links');
  assert.equal(walked.status, 0);
  assert.match(walked.stdout, /legacy_links=1 \(read under a compatibility mode, not conformant to draft §6\.7\)/);
  assert.match(walked.stdout, /read as a legacy link because --allow-payload-only-links was given: read under a compatibility mode/);
  assert.equal(JSON.parse(explore(dir, '--allow-payload-only-links', '--json').stdout).conformant, false);
  const html = replay(dir, '--allow-payload-only-links', '--audit-report');
  assert.equal(html.status, 0);
  assert.match(html.stdout, /<th>Legacy links<\/th><td>1 payload-only/);
});

test('cli: --strict switches --allow-payload-only-links off on both paths', () => {
  const dir = pair(payloadOnly, {});
  assert.equal(replay(dir, '--allow-payload-only-links', '--strict').status, 1);
  const e = explore(dir, '--allow-payload-only-links', '--strict', '--json');
  assert.equal(e.status, 1);
  assert.equal(JSON.parse(e.stdout).code, 'chain_break');
});

test('cli: replay names a new chain in the terminal and counts the chains', () => {
  const dir = mkdtempSync(join(tmpdir(), 'acta-payload-only-'));
  const a = envelope(fields(1));
  const b = envelope(fields(2, { previousReceiptHash: whole(a) }));
  const c = envelope(fields(3));
  writeFileSync(join(dir, 'receipts.jsonl'), [a, b, c].map((r) => JSON.stringify(r)).join('\n') + '\n');
  const r = replay(dir);
  assert.equal(r.status, 0, r.stdout);
  assert.match(r.stdout, /Chains: {6}2/);
  assert.match(r.stdout, /Line 3: starts a new chain: it has no previousReceiptHash, so it is not linked to line 2/);
});

test('cli: a link that is not a string is refused with JSON out and exit 1, the code a single receipt gets', () => {
  const dir = mkdtempSync(join(tmpdir(), 'acta-payload-only-'));
  const a = envelope(fields(1));
  const b = envelope(fields(2, { previousReceiptHash: 7 }));
  writeFileSync(join(dir, 'receipts.jsonl'), `${JSON.stringify(a)}\n${JSON.stringify(b)}\n`);
  const r = replay(dir, '--json');
  assert.equal(r.status, 1, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.chainBreaks, 1);
  assert.ok(report.errors.includes('Line 2: malformed_chain_link'), report.errors.join('; '));
  const single = run(['--stdin', '--key', publicKey, '--json'], JSON.stringify(b));
  assert.equal(single.status, 1);
  assert.equal(JSON.parse(single.stdout).error, 'malformed_chain_link');
});

test('cli: --strict also disables the legacy canonicalization on the replay path, as on a single file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'acta-payload-only-'));
  const legacy = envelope({ ...fields(1), nested: { '2': 2, '10': 10 } }, legacyCanonicalize);
  writeFileSync(join(dir, 'receipts.jsonl'), `${JSON.stringify(legacy)}\n`);
  assert.equal(replay(dir).status, 2);
  const allowed = replay(dir, '--allow-legacy-canonicalization', '--json');
  assert.equal(allowed.status, 0, allowed.stdout);
  assert.match(JSON.parse(allowed.stdout).warnings[0], /not RFC 8785/);
  const strict = replay(dir, '--allow-legacy-canonicalization', '--strict', '--json');
  // A historical encoding is undecidable, as on a single file, and replay exits 2 for it from 0.10.26 (-04 §5.3).
  assert.equal(strict.status, 2);
  assert.equal(JSON.parse(strict.stdout).outcome, 'undecidable');
  assert.deepEqual(JSON.parse(strict.stdout).errors, ['Line 1: legacy_non_jcs_signature']);
});

test('cli: --strict also refuses an embedded key on the replay path, as on a single file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'acta-payload-only-'));
  const embedded = envelope({ ...fields(1), public_key: publicKey });
  writeFileSync(join(dir, 'receipts.jsonl'), `${JSON.stringify(embedded)}\n`);
  const file = join(dir, 'receipts.jsonl');
  assert.equal(run(['--replay-chain', file, '--allow-embedded-key']).status, 0);
  const strict = run(['--replay-chain', file, '--allow-embedded-key', '--strict', '--json']);
  // An embedded key refused leaves the signature unchecked: undecidable, exit 2 from 0.10.26 (-04 §5.3).
  assert.equal(strict.status, 2);
  assert.equal(JSON.parse(strict.stdout).outcome, 'undecidable');
  assert.deepEqual(JSON.parse(strict.stdout).errors, ['Line 1: embedded_key_rejected']);
  assert.match(strict.stderr, /--strict overrides --allow-embedded-key/);
});
