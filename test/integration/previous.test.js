/**
 * --previous through the CLI: one receipt checked against the receipt the caller says it follows. The receipt must
 * name that receipt's draft §6.7 link, and an absent, null or different link is a chain_break (exit 1) that says
 * which. A payload-only link is refused unless --allow-payload-only-links is given, and --strict disables that flag.
 * One run checks the signature, the key window and the link, in that order. Where --previous would be dropped, it is
 * refused (exit 2).
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
const secret = new Uint8Array(32).fill(41);
const publicKey = bytesToHex(ed25519.getPublicKey(secret));
const KID = 'test:previous';
const sha = (value) => createHash('sha256').update(canonicalize(value)).digest('hex');
const sign = (payload, key = secret) => ({ payload, signature: { alg: 'EdDSA', kid: KID, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), key)) } });
const fields = (n, extra = {}) => ({ type: 'protectmcp:decision', tool_name: `records.${n}`, decision: 'allow', spec: 'draft-farley-acta-signed-receipts-03', issued_at: `2026-10-20T00:00:0${n}Z`, ...extra });
const whole = (r) => `sha256:${sha(r)}`;

const dir = mkdtempSync(join(tmpdir(), 'acta-previous-'));
const write = (name, value) => { const path = join(dir, name); writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value)); return path; };
const jwks = write('keys.json', { keys: [{ kty: 'OKP', crv: 'Ed25519', kid: KID, x: Buffer.from(publicKey, 'hex').toString('base64url'), valid_from: '2026-10-01T00:00:00Z', valid_until: '2026-11-01T00:00:00Z' }] });
const first = sign(fields(1));
const firstPath = write('first.json', first);
/** A second receipt, signed, whose payload gets `extra` (a link or none). */
const second = (extra, name = `second-${Math.random().toString(16).slice(2)}.json`) => write(name, sign(fields(2, extra)));
const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
const check = (receiptPath, ...extra) => {
  const r = run(receiptPath, '--key', publicKey, '--previous', firstPath, '--json', ...extra);
  return { status: r.status, report: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr };
};

test('cli: --previous passes a receipt that names the one supplied, in either §6.7 form (exit 0)', () => {
  for (const [link, form] of [[whole(first), 'sha256'], [whole(first).slice(7), 'legacy-bare-hex']]) {
    const { status, report } = check(second({ previousReceiptHash: link }));
    assert.equal(status, 0, JSON.stringify(report));
    assert.equal(report.previous.result, 'linked');
    assert.equal(report.previous.form, form);
    assert.equal(report.previous.expected, whole(first));
    assert.ok(report.tier.features.includes('chain-linkage'), 'a link checked against the receipt supplied is verified');
    assert.ok(!report.tier.declaredFeatures.includes('chain-linkage'));
  }
});

test('cli: a receipt that names no predecessor does not follow the one supplied: absent and null are chain breaks (exit 1)', () => {
  const absent = check(second({}));
  assert.equal(absent.status, 1);
  assert.equal(absent.report.error, 'chain_break');
  assert.equal(absent.report.previous.result, 'absent');
  assert.match(absent.report.detail, /has no previousReceiptHash, so it does not follow the receipt given with --previous/);
  const nulled = check(second({ previousReceiptHash: null }));
  assert.equal(nulled.status, 1);
  assert.equal(nulled.report.error, 'chain_break');
  assert.equal(nulled.report.previous.result, 'null');
  assert.match(nulled.report.detail, /is null/);
});

test('cli: a link to another receipt is a chain break that names both links (exit 1)', () => {
  const other = sign(fields(3));
  const { status, report } = check(second({ previousReceiptHash: whole(other) }));
  assert.equal(status, 1);
  assert.equal(report.error, 'chain_break');
  assert.equal(report.previous.result, 'mismatch');
  assert.ok(report.detail.includes(whole(other)) && report.detail.includes(whole(first)), report.detail);
});

test('cli: a payload-only link is refused unless --allow-payload-only-links is given, and --strict disables that flag', () => {
  const path = second({ previousReceiptHash: `sha256:${sha(first.payload)}` });
  const refused = check(path);
  assert.equal(refused.status, 1);
  assert.equal(refused.report.error, 'chain_break');
  assert.equal(refused.report.previous.result, 'payload-only');
  assert.match(refused.report.detail, /payload alone.*--allow-payload-only-links/);
  const read = check(path, '--allow-payload-only-links');
  assert.equal(read.status, 0, JSON.stringify(read.report));
  assert.equal(read.report.previous.result, 'legacy-payload');
  assert.match(read.report.warning, /read as a legacy link because --allow-payload-only-links was given/);
  const strict = check(path, '--allow-payload-only-links', '--strict');
  assert.equal(strict.status, 1);
  assert.equal(strict.report.previous.result, 'payload-only');
});

test('cli: a link in no §6.7 form keeps its own code with --previous', () => {
  const upper = check(second({ previousReceiptHash: `sha256:${sha(first).toUpperCase()}` }));
  assert.equal(upper.status, 1);
  assert.equal(upper.report.error, 'malformed_chain_link');
  assert.equal(upper.report.previous.result, 'malformed');
  const other = check(second({ previousReceiptHash: `sha512:${'ab'.repeat(64)}` }));
  assert.equal(other.status, 2);
  assert.equal(other.report.error, 'unsupported_chain_hash_algorithm');
  assert.equal(other.report.previous.result, 'unsupported');
});

test('cli: with --jwks, one run checks the signature, the key window and the link, in that order', () => {
  const viaJwks = (path, ...extra) => {
    const r = run(path, '--jwks', jwks, '--previous', firstPath, '--json', ...extra);
    return { status: r.status, report: JSON.parse(r.stdout) };
  };
  const good = viaJwks(second({ previousReceiptHash: whole(first) }));
  assert.equal(good.status, 0, JSON.stringify(good.report));
  assert.equal(good.report.keyStatus.result, 'inside');
  assert.equal(good.report.previous.result, 'linked');
  // Signed by another key under the same kid, and linked to nothing: the signature is reported, not the link.
  const forged = write('forged.json', sign(fields(2, {}), new Uint8Array(32).fill(42)));
  const bad = viaJwks(forged);
  assert.equal(bad.status, 1);
  assert.equal(bad.report.error, 'invalid_signature');
  assert.equal(bad.report.previous.result, 'absent', 'the link is still reported');
  // Issued before the key's window, and linked to nothing: the window is reported before the link.
  const early = write('early.json', sign(fields(2, { issued_at: '2026-09-01T00:00:00Z' })));
  const outside = viaJwks(early);
  assert.equal(outside.status, 1);
  assert.equal(outside.report.error, 'key_outside_validity_window');
  // Inside the window, and linked to nothing: now the link.
  const unlinked = viaJwks(second({}));
  assert.equal(unlinked.status, 1);
  assert.equal(unlinked.report.error, 'chain_break');
  assert.equal(unlinked.report.keyStatus.result, 'inside');
});

test('cli: the terminal names what the link was', () => {
  const r = run(second({}), '--key', publicKey, '--previous', firstPath, '--no-sigil');
  assert.equal(r.status, 1);
  assert.match(r.stdout, /Previous: +.*first\.json: does not follow it\. The receipt has no previousReceiptHash/);
  assert.match(r.stdout, /Error: +chain_break/);
});

test('cli: --previous is refused where it would be dropped, and nothing is verified (exit 2)', () => {
  const linked = second({ previousReceiptHash: whole(first) });
  const chain = write('receipts.jsonl', `${JSON.stringify(first)}\n`);
  const cases = [
    [['--replay-chain', chain, '--key', publicKey, '--previous', firstPath], /does not apply to --replay-chain/],
    [['chain', 'explore', linked, '--previous', firstPath], /does not apply to verify chain/],
    [[linked, '--bundle', '--previous', firstPath], /does not apply to --bundle/],
    [[linked, '--key', publicKey, '--previous'], /needs the file of the receipt this one follows/],
    [[linked, '--key', publicKey, '--previous', join(dir, 'missing.json')], /--previous .*missing\.json/],
    [[linked, '--key', publicKey, '--previous', write('array.json', [first])], /holds no receipt/],
    [[fileURLToPath(new URL('../../samples/sample-gate-tuple.json', import.meta.url)), '--previous', firstPath], /checks the link of one Ed25519 receipt/],
  ];
  for (const [args, message] of cases) {
    const r = run(...args);
    assert.equal(r.status, 2, `${args.join(' ')}: ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, message, args.join(' '));
    assert.match(r.stderr, /Nothing was verified \(exit 2\)/, args.join(' '));
  }
});
