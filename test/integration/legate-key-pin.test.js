/**
 * --key on the standard files and run manifests: the key a proof request, an admission decision, a run manifest or an action assurance
 * bundle is signed with must be the key given (draft §9.5). Before, the bundled core checked each file against the key
 * it carries and --key was not read, so a standard or a decision re-signed with a fresh key verified, exit 0, with the
 * real recipient key pinned and --strict; and a bundle was valid, reported as pinned, under any --key.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../../src/util/canonical.js';

const cli = fileURLToPath(new URL('../../cli.js', import.meta.url));
const fixtures = fileURLToPath(new URL('../fixtures/legate/', import.meta.url));
const core = readFileSync(fileURLToPath(new URL('../../src/engines/legate-core.mjs', import.meta.url)), 'utf8');
const fixture = (name) => JSON.parse(readFileSync(join(fixtures, name), 'utf8'));
const dir = mkdtempSync(join(tmpdir(), 'acta-legate-pin-'));
const write = (name, value) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(value)); return p; };
const run = (...args) => spawnSync(process.execPath, [cli, ...args, '--json'], { encoding: 'utf8', timeout: 30000, env: { ...process.env, NO_COLOR: '1', CI: '1' } });
const json = (...args) => { const r = run(...args); return { status: r.status, report: JSON.parse(r.stdout), stderr: r.stderr }; };
const sha = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

// A key the recipient never held. Deterministic, test only.
const secret = new Uint8Array(32).fill(0x42);
const attackerKey = bytesToHex(ed25519.getPublicKey(secret));
const otherKey = bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(0x07)));

// The signed members, read from the core so the preimage is exactly the one it checks.
const unsignedKeys = (name) => JSON.parse(`[${new RegExp(`var ${name} = \\[([^\\]]*)\\]`).exec(core)[1]}]`);
const preimage = (domain, value, keys) => `${domain}\0${canonicalize(Object.fromEntries(keys.filter((k) => value[k] !== undefined).map((k) => [k, value[k]])))}`;

/** The report's reproduction: the shipped file with the recipient key swapped for the attacker's and re-signed. */
function resigned(name, domain, keysName, edit = () => {}) {
  const original = fixture(name);
  const keys = unsignedKeys(keysName);
  assert.equal(sha(preimage(domain, original, keys)), original.digest, `${name}: the test reproduces the shipped preimage`);
  const forged = structuredClone(original);
  forged.recipient = { ...forged.recipient, verification_key: attackerKey, key_id: `recipient:${sha(attackerKey).slice(0, 16)}` };
  edit(forged);
  const pre = preimage(domain, forged, keys);
  forged.digest = sha(pre);
  forged.signature = { ...forged.signature, value: bytesToHex(ed25519.sign(utf8ToBytes(pre), secret)) };
  return { original, forged };
}

test('cli: a standard re-signed with another key is invalid under --key <the real recipient key> (key_mismatch, exit 1)', () => {
  const { original, forged } = resigned('proof-request.json', 'scopeblind.proof-request.v1', 'REQUEST_UNSIGNED_KEYS2');
  const file = write('proof-request-forged.json', forged);
  for (const extra of [[], ['--strict']]) {
    const { status, report } = json(file, '--key', original.recipient.verification_key, ...extra);
    assert.equal(status, 1, JSON.stringify(report));
    assert.equal(report.valid, false);
    assert.equal(report.error, 'key_mismatch');
    assert.deepEqual(report.checks.find((c) => c.id === 'key_pin')?.ok, false);
    assert.equal(report.in_plain_words, undefined, 'a standard signed with another key is not read back');
  }
  // The genuine standard under its own recipient key, in either case, is valid and says the pin held.
  const genuine = json(join(fixtures, 'proof-request.json'), '--key', original.recipient.verification_key.toUpperCase());
  assert.equal(genuine.status, 0, JSON.stringify(genuine.report));
  assert.equal(genuine.report.checks.find((c) => c.id === 'key_pin')?.ok, true);
});

test('cli: a recipient decision re-signed with another key is invalid under --key <the real recipient key> (exit 1)', () => {
  const { original, forged } = resigned('admission-decision.json', 'scopeblind.admission-decision.v1', 'DECISION_UNSIGNED_KEYS2', (d) => {
    d.reason = 'Forged: accepted by a key the recipient never held.';
  });
  const file = write('admission-decision-forged.json', forged);
  const { status, report } = json(file, '--key', original.recipient.verification_key, '--strict');
  assert.equal(status, 1, JSON.stringify(report));
  assert.equal(report.error, 'key_mismatch');
  const genuine = json(join(fixtures, 'admission-decision.json'), '--key', original.recipient.verification_key);
  assert.equal(genuine.status, 0, JSON.stringify(genuine.report));
});

test('cli: a run manifest under a --key that did not sign it is invalid (key_mismatch, exit 1)', () => {
  const manifest = fixture('run-manifest.json');
  const wrong = json(join(fixtures, 'run-manifest.json'), '--key', otherKey);
  assert.equal(wrong.status, 1, JSON.stringify(wrong.report));
  assert.equal(wrong.report.error, 'key_mismatch');
  assert.equal(wrong.report.binding, 'unbound');
  const right = json(join(fixtures, 'run-manifest.json'), '--key', manifest.signer.verification_key);
  assert.equal(right.status, 0, JSON.stringify(right.report));
  assert.equal(right.report.checks.find((c) => c.id === 'key_pin')?.ok, true);
});

test('cli: an action bundle is valid under --key only when its gate request and receipt are signed with it', () => {
  const bundle = fixture('action-bundle.json');
  const file = join(fixtures, 'action-bundle.json');
  const wrong = json(file, '--key', otherKey);
  assert.equal(wrong.status, 1, JSON.stringify(wrong.report));
  assert.equal(wrong.report.error, 'key_mismatch');
  assert.equal(wrong.report.signers_pinned, false);
  assert.equal(wrong.report.verification.pins_match, false);
  const right = json(file, '--key', bundle.request.issuer.verification_key);
  assert.equal(right.status, 0, JSON.stringify(right.report));
  assert.equal(right.report.signers_pinned, true);
  // With no key the bundle rests only on the keys it carries: undecidable, unless --allow-carried-key accepts it.
  const none = json(file);
  assert.equal(none.status, 2, JSON.stringify(none.report).slice(0, 300));
  assert.equal(none.report.signers_pinned, false);
  assert.equal(json(file, '--allow-carried-key').status, 0);
});

test('cli: --maintainer-key is refused where it would not be applied (exit 2), never dropped', () => {
  const manifest = fixture('run-manifest.json');
  const standard = fixture('run-standard.json');
  for (const [file, label] of [[join(fixtures, 'run-manifest.json'), 'a run manifest without --standard'], [join(fixtures, 'proof-request.json'), 'a standard']]) {
    const r = run(file, '--maintainer-key', otherKey);
    assert.equal(r.status, 2, `${label}: ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, /--maintainer-key pins the key that signed the standard/);
  }
  // With --standard it is applied, as before: the wrong maintainer key does not bind (exit 1), the right one does.
  const wrongPin = run(join(fixtures, 'run-manifest.json'), '--standard', join(fixtures, 'run-standard.json'), '--maintainer-key', otherKey);
  assert.equal(wrongPin.status, 1, wrongPin.stdout);
  assert.equal(JSON.parse(wrongPin.stdout).checks.find((c) => c.id === 'maintainer_pin')?.ok, false);
  const rightPin = run(join(fixtures, 'run-manifest.json'), '--standard', join(fixtures, 'run-standard.json'), '--maintainer-key', standard.recipient.verification_key);
  assert.equal(JSON.parse(rightPin.stdout).checks.find((c) => c.id === 'maintainer_pin')?.ok, true);
  assert.ok(manifest.signer.verification_key);
});
