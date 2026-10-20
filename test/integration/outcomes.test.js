/**
 * The three outcomes of §5.3 of the -04 editor's copy (VeritasActa/drafts) through the CLI, from 0.10.26: a verification making several checks is invalid
 * if any check ran and failed, even when another could not run; undecidable if none failed and one could not run;
 * valid only when every check that applies passed. The exit status tells them apart (0, 1, 2), on a single receipt,
 * with --previous, and on --replay-chain, which takes keys from --jwks by kid. Key windows read only timestamps that
 * write their UTC offset out, so a result never depends on the machine's time zone; a key given with --key has no
 * window, and its validity at issuance is reported as not established.
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
import { parseTimestamp, checkKeyWindow } from '../../src/util/key-window.js';
import { combineChecks } from '../../src/engines/ed25519-receipt.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const KEYS = { k1: new Uint8Array(32).fill(51), k2: new Uint8Array(32).fill(52) };
const pub = (kid) => bytesToHex(ed25519.getPublicKey(KEYS[kid]));
const sha = (value) => createHash('sha256').update(canonicalize(value)).digest('hex');
const sign = (payload, kid = 'k1') => ({ payload, signature: { alg: 'EdDSA', kid, sig: bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), KEYS[kid])) } });
const fields = (n, extra = {}) => ({ type: 'protectmcp:decision', tool_name: `records.${n}`, decision: 'allow', spec: 'draft-farley-acta-signed-receipts-03', issued_at: `2026-03-15T00:00:0${n}Z`, ...extra });
const WINDOW = { valid_from: '2026-01-01T00:00:00Z', valid_until: '2026-06-01T00:00:00Z' };

const dir = mkdtempSync(join(tmpdir(), 'acta-outcomes-'));
let n = 0;
const write = (value, name = `f${n++}.json`) => { const path = join(dir, name); writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value)); return path; };
const jwk = (kid, window = WINDOW) => ({ kty: 'OKP', crv: 'Ed25519', kid, x: Buffer.from(pub(kid), 'hex').toString('base64url'), ...window });
const keySet = (...keys) => write({ keys });
const run = (args, env = {}) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 20000, env: { ...process.env, NO_COLOR: '1', CI: '1', ...env } });
const json = (args, env) => { const r = run([...args, '--json'], env); return { status: r.status, report: JSON.parse(r.stdout), stderr: r.stderr }; };

test('timestamps: only RFC 3339 date-times with their offset written out are read, and their calendar is checked', () => {
  assert.equal(parseTimestamp('2026-05-31T23:30:00Z').ms, Date.UTC(2026, 4, 31, 23, 30));
  assert.equal(parseTimestamp('2026-05-31T19:30:00-04:00').ms, Date.UTC(2026, 4, 31, 23, 30));
  assert.equal(parseTimestamp('2026-06-01T01:00:00.250+01:30').ms, Date.UTC(2026, 4, 31, 23, 30, 0, 250));
  assert.equal(parseTimestamp('2028-02-29T00:00:00Z').ms, Date.UTC(2028, 1, 29));
  for (const [value, cause] of [
    ['2026-05-31T23:30:00', /no UTC offset/], ['2026-05-31', /date without a time/], ['Jan 1 2026', /not an RFC 3339/],
    [null, /is null/], [1767225600, /is a number/], ['2026-02-29T00:00:00Z', /not a date and time that exists/], ['2026-04-31T00:00:00Z', /not a date and time that exists/],
    ['2026-01-01T24:00:00Z', /not a date and time that exists/], ['2026-01-01T00:00:00+24:00', /offset that does not exist/], ['2026-01-01T00:00:00+0100', /not an RFC 3339/],
  ]) assert.match(parseTimestamp(value).cause ?? '', cause, String(value));
});

test('key window: a bound written as null cannot be applied, while an absent bound leaves the window open', () => {
  assert.equal(checkKeyWindow({ window: { valid_from: null, valid_until: WINDOW.valid_until }, issuedAt: '2026-03-15T00:00:00Z', keySource: 'jwks' }).error, 'key_window_unverifiable');
  assert.equal(checkKeyWindow({ window: { valid_until: WINDOW.valid_until }, issuedAt: '2020-03-15T00:00:00Z', keySource: 'jwks' }).status, 'inside');
});

for (const TZ of ['UTC', 'America/New_York']) {
  test(`key window, TZ=${TZ}: an issued_at without an offset is undecidable, and the same instant with one is read alike`, () => {
    const keys = keySet(jwk('k1'));
    const at = (issuedAt) => json([write(sign(fields(1, { issued_at: issuedAt }))), '--jwks', keys], { TZ });
    // Inside the window read as UTC, outside it read as New York time: so it is not read at all.
    const local = at('2026-05-31T23:30:00');
    assert.equal(local.status, 2);
    assert.equal(local.report.error, 'key_window_unverifiable');
    assert.equal(local.report.outcome, 'undecidable');
    assert.match(local.report.detail, /issued_at "2026-05-31T23:30:00" has no UTC offset/);
    for (const instant of ['2026-05-31T23:30:00Z', '2026-05-31T19:30:00-04:00', '2026-06-01T00:30:00+01:00']) {
      const inside = at(instant);
      assert.equal(inside.status, 0, `${instant}: ${JSON.stringify(inside.report.keyStatus)}`);
      assert.equal(inside.report.keyStatus.result, 'inside', instant);
    }
    assert.equal(at('2026-06-01T00:30:00Z').status, 1);
  });

  test(`key window, TZ=${TZ}: a bound that is a date alone, prose or null is undecidable and named`, () => {
    for (const [bounds, cause] of [
      [{ valid_from: '2026-01-01', valid_until: WINDOW.valid_until }, /valid_from "2026-01-01" is a date without a time and UTC offset/],
      [{ valid_from: WINDOW.valid_from, valid_until: 'Jun 1 2026' }, /valid_until "Jun 1 2026" is not an RFC 3339 date-time/],
      [{ valid_from: null, valid_until: WINDOW.valid_until }, /valid_from null is null, not a timestamp/],
    ]) {
      const r = json([write(sign(fields(1))), '--jwks', keySet(jwk('k1', bounds))], { TZ });
      assert.equal(r.status, 2, JSON.stringify(bounds));
      assert.equal(r.report.error, 'key_window_unverifiable');
      assert.match(r.report.detail, cause);
    }
  });
}

test('a key given with --key has no source for a window: validity at issuance is not established, and the exit is unchanged', () => {
  const file = write(sign(fields(1)));
  const r = json([file, '--key', pub('k1')]);
  assert.equal(r.status, 0);
  assert.equal(r.report.keyStatus.result, 'not_established');
  const text = run([file, '--key', pub('k1'), '--no-sigil']);
  assert.equal(text.status, 0);
  assert.match(text.stdout, /Key window: none for a key given directly; key validity at issuance not established\./);
});

test('combineChecks: a failure outranks a check that could not run, and the first failure in order is named', () => {
  assert.deepEqual(combineChecks({ signature: { result: 'pass' }, chain_link: { result: 'undecidable', code: 'unsupported_chain_hash_algorithm' }, key_window: { result: 'fail', code: 'key_outside_validity_window' } }),
    { valid: false, outcome: 'invalid', error: 'key_outside_validity_window', check: 'key_window' });
  assert.deepEqual(combineChecks({ signature: { result: 'pass' }, chain_link: { result: 'undecidable', code: 'unsupported_chain_hash_algorithm' }, key_window: { result: 'not_established' } }),
    { valid: false, outcome: 'undecidable', error: 'unsupported_chain_hash_algorithm', check: 'chain_link' });
  assert.deepEqual(combineChecks({ signature: { result: 'pass' }, chain_link: { result: 'absent' }, key_window: { result: 'not_run' } }), { valid: true, outcome: 'valid' });
});

test('single receipt: a check made after the receipt\'s own keeps the outcome in step (--tier)', () => {
  const file = write(sign(fields(1)));
  const r = json([file, '--key', pub('k1'), '--tier', '3']);
  assert.equal(r.status, 2);
  assert.equal(r.report.valid, false);
  assert.equal(r.report.error, 'tier_not_achieved');
  assert.equal(r.report.outcome, 'undecidable', 'the outcome is not left at valid when a later check refuses the receipt');
});

test('single receipt: a link naming another algorithm is undecidable, but a window it falls outside makes it invalid', () => {
  const other = { previousReceiptHash: `sha512:${'ab'.repeat(64)}` };
  const keys = keySet(jwk('k1'));
  const undecided = json([write(sign(fields(1, other))), '--jwks', keys]);
  assert.equal(undecided.status, 2);
  assert.equal(undecided.report.error, 'unsupported_chain_hash_algorithm');
  assert.equal(undecided.report.checks.key_window.result, 'pass');
  const outside = json([write(sign(fields(1, { ...other, issued_at: '2026-07-01T00:00:00Z' }))), '--jwks', keys]);
  assert.equal(outside.status, 1, '0.10.25 exited 2 here: the window was not applied once the link was undecidable');
  assert.equal(outside.report.outcome, 'invalid');
  assert.equal(outside.report.error, 'key_outside_validity_window');
  assert.equal(outside.report.checks.chain_link.result, 'undecidable');
});

test('single receipt: a malformed link makes a receipt invalid even when no key can check its signature', () => {
  const malformed = write(sign(fields(1, { previousReceiptHash: `sha256:${'AB'.repeat(32)}` })));
  const noKey = json([malformed]);
  assert.equal(noKey.status, 1);
  assert.equal(noKey.report.error, 'malformed_chain_link');
  assert.equal(noKey.report.checks.signature.code, 'no_public_key');
  const unknownKid = json([malformed, '--jwks', keySet(jwk('k2'))]);
  assert.equal(unknownKid.status, 1);
  assert.equal(unknownKid.report.checks.signature.code, 'jwks_fetch_failed');
  const linkless = json([write(sign(fields(1))), '--jwks', keySet(jwk('k2'))]);
  assert.equal(linkless.status, 2);
  assert.equal(linkless.report.error, 'jwks_fetch_failed');
  assert.match(linkless.report.detail, /No key with kid "k1"/);
});

test('--previous: a link naming another algorithm is undecidable, and invalid beside a window it falls outside', () => {
  const before = write(sign(fields(1)));
  const keys = keySet(jwk('k1'));
  const link = { previousReceiptHash: `sha512:${'cd'.repeat(64)}` };
  const undecided = json([write(sign(fields(2, link))), '--jwks', keys, '--previous', before]);
  assert.equal(undecided.status, 2);
  assert.equal(undecided.report.previous.result, 'unsupported');
  assert.equal(undecided.report.checks.previous.result, 'undecidable');
  const outside = json([write(sign(fields(2, { ...link, issued_at: '2025-12-01T00:00:00Z' }))), '--jwks', keys, '--previous', before]);
  assert.equal(outside.status, 1);
  assert.equal(outside.report.error, 'key_outside_validity_window');
});

test('--previous: a payload-only link read under the compatibility flag is marked as not conformant', () => {
  const first = sign(fields(1));
  const r = json([write(sign(fields(2, { previousReceiptHash: `sha256:${sha(first.payload)}` }))), '--key', pub('k1'), '--previous', write(first), '--allow-payload-only-links']);
  assert.equal(r.status, 0);
  assert.equal(r.report.conformant, false);
  assert.match(r.report.warning, /read under a compatibility mode, not conformant to draft §6\.7/);
});

/** A JSONL file of receipts, each linked to the one before by the §6.7 link unless the receipt carries its own. */
function chain(...specs) {
  const out = [];
  for (const [i, spec] of specs.entries()) {
    if (typeof spec === 'string') { out.push(spec); continue; }
    const { kid = 'k1', extra = {}, unlinked = false } = spec;
    const prev = out.length && typeof out[out.length - 1] !== 'string' ? out[out.length - 1] : null;
    const link = !unlinked && prev && !('previousReceiptHash' in extra) ? { previousReceiptHash: `sha256:${sha(prev)}` } : {};
    out.push(sign(fields(i + 1, { ...link, ...extra }), kid));
  }
  return write(out.map((r) => (typeof r === 'string' ? r : JSON.stringify(r))).join('\n') + '\n', `chain${n++}.jsonl`);
}
const replay = (file, ...extra) => json(['--replay-chain', file, ...extra]);

test('replay: keys come from --jwks by each receipt\'s kid, with each key\'s window applied', () => {
  const keys = keySet(jwk('k1'), jwk('k2', { valid_from: '2026-03-01T00:00:00Z' }));
  const good = replay(chain({ kid: 'k1' }, { kid: 'k2' }, { kid: 'k1' }), '--jwks', keys);
  assert.equal(good.status, 0, JSON.stringify(good.report.errors));
  assert.equal(good.report.outcome, 'valid');
  assert.equal(good.report.verified, 3);
  assert.deepEqual(good.report.receipts.map((r) => r.keyStatus.result), ['inside', 'inside', 'inside']);
  const early = replay(chain({ kid: 'k1' }, { kid: 'k2', extra: { issued_at: '2026-02-01T00:00:00Z' } }), '--jwks', keys);
  assert.equal(early.status, 1);
  assert.deepEqual(early.report.errors, ['Line 2: key_outside_validity_window']);
});

test('replay: --key takes precedence over --jwks, and a key set that cannot be read stops the replay (exit 2)', () => {
  const file = chain({ kid: 'k1' }, { kid: 'k1' });
  assert.equal(replay(file, '--key', pub('k1'), '--jwks', join(dir, 'absent.json')).status, 0);
  const r = run(['--replay-chain', file, '--jwks', join(dir, 'absent.json')]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--jwks .*absent\.json: JWKS fetch error/);
  assert.match(r.stderr, /Nothing was verified \(exit 2\)/);
});

test('replay exits 2 when nothing failed and a line could not be checked, and 1 when anything failed', () => {
  const keys = keySet(jwk('k1'));
  const unknown = replay(chain({ kid: 'k1' }, { kid: 'k2' }), '--jwks', keys);
  assert.equal(unknown.status, 2);
  assert.equal(unknown.report.outcome, 'undecidable');
  assert.equal(unknown.report.undecidable, 1);
  assert.equal(unknown.report.failed, 0);
  assert.match(unknown.report.errors[0], /^Line 2: jwks_fetch_failed \(No key with kid "k2" in JWKS\)/);
  const malformedJson = replay(chain({ kid: 'k1' }, '{"not json'), '--jwks', keys);
  assert.equal(malformedJson.status, 2);
  assert.match(malformedJson.report.errors[0], /^Line 2: malformed JSON: /);
  const otherAlgorithm = replay(chain({ kid: 'k1' }, { kid: 'k1', extra: { previousReceiptHash: `sha512:${'ab'.repeat(64)}` } }), '--jwks', keys);
  assert.equal(otherAlgorithm.status, 2, 'a link naming another algorithm is not a chain break');
  assert.equal(otherAlgorithm.report.chainBreaks, 0);
  assert.match(otherAlgorithm.report.warnings.join('\n'), /names a hash algorithm other than sha256, so whether it follows line 1 is not decided/);
  const broken = replay(chain({ kid: 'k1' }, { kid: 'k2' }, { kid: 'k1', extra: { previousReceiptHash: `sha256:${'0'.repeat(64)}` } }), '--jwks', keys);
  assert.equal(broken.status, 1);
  assert.equal(broken.report.outcome, 'invalid');
  assert.equal(broken.report.chainBreaks, 1);
  assert.equal(broken.report.undecidable, 1);
  const text = run(['--replay-chain', chain({ kid: 'k1' }, { kid: 'k2' }), '--jwks', keys]);
  assert.match(text.stdout, /Outcome: +not checked \(undecidable\) \(exit 2\)/);
  assert.match(text.stdout, /Not checked: 1/);
});

test('replay: an undecidable link beside a window the receipt falls outside is invalid', () => {
  const r = replay(chain({ kid: 'k1' }, { kid: 'k1', extra: { previousReceiptHash: `sha512:${'ab'.repeat(64)}`, issued_at: '2026-07-01T00:00:00Z' } }), '--jwks', keySet(jwk('k1')));
  assert.equal(r.status, 1);
  assert.deepEqual(r.report.errors, ['Line 2: key_outside_validity_window']);
});
