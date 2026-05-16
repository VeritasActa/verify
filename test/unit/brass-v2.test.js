/**
 * Unit tests for BRASS v2 scaffolding.
 *
 * Verifies the three hardening properties:
 *   1. Length-prefixed hashing rejects concat-collision inputs that
 *      plain concatenation would treat as equivalent.
 *   2. Nullifier derivation is bound to the issuer public key Y.
 *   3. Single-variable πC verifier accepts a well-formed proof and
 *      rejects a tampered one.
 *
 * These are scaffold tests — not wired into production verification,
 * but ensure the v0.6.0 migration target is implementable.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  H_LP,
  H_LPlabel,
  deriveNullifier_v2,
  piCVerify_v2,
} from '../../src/util/voprf-crypto-v2.js';
import { G, H, modN, bytesToBig } from '../../src/util/voprf-crypto.js';

// Build a concrete (P, M, c, r, AAD, kid) tuple where r is known and
// c is recomputed — effectively a honest-prover scenario.
function honestPiCTuple({ AADr = 'aad', kid = 'test-kid' } = {}) {
  const privScalar = 7n;
  const r = 9n;
  const P = G.multiply(privScalar);
  const M = P.multiply(r);
  const A = P.multiply(r); // honest prover picks k=r; here we set A=r·P so c=0 works trivially

  // Real Fiat-Shamir: pick random k, A=k·P, derive c, s = k - c·r.
  // For a verifier test we construct a valid (c, r') tuple:
  // choose k, compute A = k·P, compute c = H_LP(…, A, …), then r' = k - c·r.
  const k = 13n;
  const Areal = P.multiply(k);
  const digest = H_LPlabel(
    'BRASS_BIND_v1',
    P.toRawBytes(true),
    M.toRawBytes(true),
    Areal.toRawBytes(true),
    AADr,
    kid
  );
  const c = modN(bytesToBig(digest));
  // response r' := k - c·r (mod N)
  const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const r2 = ((k - c * r) % N + N) % N;

  // Now the verifier reconstructs A' = r'·P + c·M. Does it match A?
  // A' = (k - c·r)·P + c·r·P = k·P = A. Yes.
  return { P, M, c, r: r2, AADr, kid };
}

test('H_LP: length-prefix distinguishes ("a","bc") from ("ab","c")', () => {
  const a = H_LP('a', 'bc');
  const b = H_LP('ab', 'c');
  assert.notDeepEqual(a, b);
});

test('H_LP: same inputs produce same digest', () => {
  const a = H_LP('alpha', 'beta');
  const b = H_LP('alpha', 'beta');
  assert.deepEqual(a, b);
});

test('H_LP vs plain H: length-prefix changes the digest', () => {
  // H is the plain-concat hash; H_LP should differ.
  const plain = H('alpha', 'beta');
  const lp = H_LP('alpha', 'beta');
  assert.notDeepEqual(plain, lp);
});

test('H_LPlabel: label changes digest', () => {
  const a = H_LPlabel('LABEL_A', 'x');
  const b = H_LPlabel('LABEL_B', 'x');
  assert.notDeepEqual(a, b);
});

test('deriveNullifier_v2: different Y ⇒ different nullifier (kid-space disjoint)', () => {
  const Y1 = G.multiply(7n);
  const Y2 = G.multiply(11n);
  const n1 = deriveNullifier_v2(Y1, 'duplicate-kid', 'epoch-1');
  const n2 = deriveNullifier_v2(Y2, 'duplicate-kid', 'epoch-1');
  assert.notDeepEqual(n1, n2);
});

test('deriveNullifier_v2: same inputs ⇒ same nullifier', () => {
  const Y = G.multiply(3n);
  const a = deriveNullifier_v2(Y, 'kid-x', 'extra');
  const b = deriveNullifier_v2(Y, 'kid-x', 'extra');
  assert.deepEqual(a, b);
});

test('deriveNullifier_v2: different kid ⇒ different nullifier', () => {
  const Y = G.multiply(3n);
  const a = deriveNullifier_v2(Y, 'kid-1');
  const b = deriveNullifier_v2(Y, 'kid-2');
  assert.notDeepEqual(a, b);
});

test('piCVerify_v2: honest prover tuple verifies', () => {
  const tup = honestPiCTuple({});
  assert.equal(piCVerify_v2(tup), true);
});

test('piCVerify_v2: tampered AAD fails verification', () => {
  const tup = honestPiCTuple({ AADr: 'aad-original' });
  const tampered = { ...tup, AADr: 'aad-tampered' };
  assert.equal(piCVerify_v2(tampered), false);
});

test('piCVerify_v2: tampered kid fails verification', () => {
  const tup = honestPiCTuple({ kid: 'kid-1' });
  const tampered = { ...tup, kid: 'kid-2' };
  assert.equal(piCVerify_v2(tampered), false);
});

test('piCVerify_v2: perturbed response r fails verification', () => {
  const tup = honestPiCTuple({});
  const bad = { ...tup, r: (tup.r + 1n) };
  assert.equal(piCVerify_v2(bad), false);
});
