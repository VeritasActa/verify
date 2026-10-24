/**
 * Public payload-format regression checks using frozen synthetic examples.
 * These check this verifier, not producer compatibility. Maintainers can also
 * supply the original shared corpus with ACTA_GOVERNED_VECTORS_FILE.
 * Expected bytes are reviewed fixture inputs, never computed by the engine.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { legateReceiptPayload } from '../../src/engines/legate-governed-receipt.js';
import { sortKeysDeep } from '../../src/util/canonical.js';

// Default is the checked-in synthetic corpus. A producer maintainer can run
// its original shared corpus explicitly without changing the standalone tests.
const VEC_PATH = process.env.ACTA_GOVERNED_VECTORS_FILE
  || new URL('../fixtures/standalone/governed-receipt-vectors.json', import.meta.url);
const VEC = JSON.parse(readFileSync(VEC_PATH, 'utf8'));
const canonical = (o) => JSON.stringify(sortKeysDeep(o));

// The checked-in corpus has these exact sizes. Any other corpus must at least be
// nonempty, so an emptied or truncated file fails instead of passing unchecked.
const CHECKED_IN = !process.env.ACTA_GOVERNED_VECTORS_FILE;
const CHECKED_IN_COUNTS = { legate_receipt_payload: 2, canonical_json: 4, gate_tuple_digest: 1 };

function cases(name) {
  const list = VEC[name];
  assert.ok(Array.isArray(list) && list.length > 0, `${name}: no cases in the corpus`);
  if (CHECKED_IN) assert.equal(list.length, CHECKED_IN_COUNTS[name], `${name}: case count`);
  return list;
}

test('verify-cli legateReceiptPayload matches the locked vectors byte-for-byte', () => {
  for (const v of cases('legate_receipt_payload')) {
    assert.equal(legateReceiptPayload(v.input), v.expected, `drift in legate receipt payload (${v.name})`);
  }
});

test('verify-cli canonical JSON (sortKeysDeep) matches the locked vectors', () => {
  for (const v of cases('canonical_json')) {
    assert.equal(canonical(v.input), v.expected, `drift in canonical JSON (${v.name})`);
  }
});

test('verify-cli gate-tuple digest is sha256 over the locked canonical payload', () => {
  for (const v of cases('gate_tuple_digest')) {
    assert.equal(canonical(v.payload), v.expected_canonical, `drift in canonical for ${v.name}`);
    const digest = bytesToHex(sha256(utf8ToBytes(canonical(v.payload))));
    assert.equal(digest, v.expected_sha256 ?? bytesToHex(sha256(utf8ToBytes(v.expected_canonical))), 'digest derivation drifted');
  }
});
