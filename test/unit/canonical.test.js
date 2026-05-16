/**
 * Unit tests for JCS canonicalization + AIP-0001 ASCII-only keys.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalize,
  canonicalHash,
  sortKeysDeep,
  assertAsciiKeys,
} from '../../src/util/canonical.js';

test('canonicalize: object keys sort lexicographically', () => {
  const out = canonicalize({ b: 1, a: 2, c: 3 });
  assert.equal(out, '{"a":2,"b":1,"c":3}');
});

test('canonicalize: nested objects deep-sort', () => {
  const out = canonicalize({ outer: { b: 1, a: 2 }, alpha: true });
  assert.equal(out, '{"alpha":true,"outer":{"a":2,"b":1}}');
});

test('canonicalize: arrays preserve order', () => {
  const out = canonicalize({ arr: [3, 1, 2] });
  assert.equal(out, '{"arr":[3,1,2]}');
});

test('canonicalize: empty object', () => {
  assert.equal(canonicalize({}), '{}');
});

test('canonicalize: null passes through', () => {
  assert.equal(canonicalize({ x: null }), '{"x":null}');
});

test('canonicalize: assertion on non-ASCII keys', () => {
  assert.throws(
    () => canonicalize({ 'naïve': 'fail' }),
    (e) => e.code === 'non_ascii_key',
  );
});

test('canonicalize: unicode values are allowed', () => {
  const out = canonicalize({ msg: 'héllo' });
  assert.ok(out.includes('héllo'));
});

test('assertAsciiKeys: detects deep non-ASCII', () => {
  assert.throws(
    () => assertAsciiKeys({ a: { b: { 'ü': 'x' } } }),
    (e) => e.code === 'non_ascii_key',
  );
});

test('canonicalHash: deterministic across runs', () => {
  const h1 = canonicalHash({ a: 1, b: 'x' });
  const h2 = canonicalHash({ b: 'x', a: 1 });
  assert.equal(h1, h2);
  assert.equal(h1.length, 64);
});

test('sortKeysDeep: arrays inside objects preserve order', () => {
  const sorted = sortKeysDeep({ z: [3, 1, 2], a: 1 });
  assert.deepEqual(sorted, { a: 1, z: [3, 1, 2] });
  assert.deepEqual(Object.keys(sorted), ['a', 'z']);
});
