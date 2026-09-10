import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from '../../src/util/canonical.js';
import { bytesToHex } from '../../src/util/hex.js';
import { verifyLegateProofPack } from '../../src/engines/legate-proof-pack.js';
import { detectFormat } from '../../src/detect.js';

// The static sample was produced by the REAL desktop runtime (legate-proof-pack.cjs
// signProofPack) and committed as a cross-implementation fixture: if this verifies,
// the open verifier agrees with the runtime byte-for-byte.
const REAL = JSON.parse(readFileSync(new URL('../../samples/legate-proof-pack.json', import.meta.url)));

// Sign a pack here the same way the runtime does, for round-trip + tamper tests.
function signPack(core, priv, pubHex) {
  const c = { ...core, type: 'scopeblind.legate.proof-pack.v1', verification_key: pubHex };
  const canonical = canonicalize({ ...c, signature: undefined, sha256: undefined, hybrid_signature: undefined });
  return {
    ...c,
    sha256: bytesToHex(sha256(utf8ToBytes(canonical))),
    signature: bytesToHex(ed25519.sign(utf8ToBytes(canonical), priv)),
  };
}

test('detectFormat routes a proof pack to the legate-proof-pack engine', () => {
  assert.equal(detectFormat(REAL).mode, 'legate-proof-pack');
});

test('a real desktop-signed proof pack verifies', () => {
  const r = verifyLegateProofPack(REAL);
  assert.equal(r.valid, true, r.error);
  assert.equal(r.format, 'legate-proof-pack');
  assert.equal(r.positionBlind, true);
  assert.equal(typeof r.restraint.blocked, 'number');
  // The fixture was generated with two observed shadow orders.
  assert.equal(r.shadow.observed, 2);
});

test('--key pins the runtime: a matching key passes, a wrong key is a mismatch', () => {
  assert.equal(verifyLegateProofPack(REAL, { publicKey: REAL.verification_key }).valid, true);
  const wrong = verifyLegateProofPack(REAL, { publicKey: 'ab'.repeat(32) });
  assert.equal(wrong.valid, false);
  assert.equal(wrong.error, 'key_mismatch');
});

test('tampering with any signed field fails verification', () => {
  const t1 = structuredClone(REAL); t1.restraint.blocked = (t1.restraint.blocked || 0) + 99;
  assert.equal(verifyLegateProofPack(t1).valid, false);
  const t2 = structuredClone(REAL); t2.shadow.would_block = 999;
  assert.equal(verifyLegateProofPack(t2).valid, false);
  const t3 = structuredClone(REAL); t3.mandate.sha256 = 'f'.repeat(64);
  assert.equal(verifyLegateProofPack(t3).valid, false);
});

test('round-trip: a freshly signed pack verifies, and a post-sign edit fails', () => {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = bytesToHex(ed25519.getPublicKey(priv));
  const pack = signPack({
    generated_at: '2026-06-22T00:00:00.000Z',
    position_blind: true,
    runtime: { name: 'Desk-1', verification_key: pub },
    mandate: { name: 'Global Macro IMA', sha256: 'a'.repeat(64), mode: 'enforce', rule_count: 9 },
    governed_actions: { evaluated: 40, allowed: 30, held: 6, blocked: 4 },
    restraint: { blocked: 4, held: 6, by_rule: [{ rule: 'class-gross-commodity', count: 4 }] },
    shadow: { observed: 120, would_block: 7, would_hold: 3, by_rule: [] },
    session_merkle_root: 'r'.repeat(64),
    receipt_count: 40,
  }, priv, pub);

  assert.equal(verifyLegateProofPack(pack).valid, true);
  const edited = { ...pack, restraint: { ...pack.restraint, blocked: 0 } };
  assert.equal(verifyLegateProofPack(edited).valid, false);
});

test('a non-pack or malformed input is rejected, not crashed', () => {
  assert.equal(verifyLegateProofPack(null).valid, false);
  assert.equal(verifyLegateProofPack({ type: 'something-else' }).valid, false);
  assert.equal(verifyLegateProofPack({ type: 'scopeblind.legate.proof-pack.v1' }).error, 'missing_signature');
});

test('a present hybrid signature is recognized and reported', () => {
  const r = verifyLegateProofPack({ ...REAL, hybrid_signature: { alg: 'ed25519+ml-dsa-65' } });
  // The hybrid field is excluded from the signed canonical, so Ed25519 still verifies,
  // and the verifier surfaces that a PQ signature is also present.
  assert.equal(r.valid, true);
  assert.equal(r.hybridSignaturePresent, true);
});
