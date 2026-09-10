/**
 * Canonical-format drift guard for the open verifier.
 *
 * Locks the Legate governed-receipt payload and the canonical-JSON algorithm
 * against the shared golden vectors in specs/governed-receipt-vectors.json. The
 * verifier is the neutral party: if its canonical/payload format drifts from the
 * producer (scopeblind-pm) or the daemon/phone, third-party verification silently
 * breaks. Fix the drift; do not edit the fixture to pass.
 *
 * @module test/unit/canonical-vectors.test
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';
import { legateReceiptPayload } from '../../src/engines/legate-governed-receipt.js';
import { sortKeysDeep } from '../../src/util/canonical.js';

const here = fileURLToPath(new URL('.', import.meta.url));
const VEC_PATH = join(here, '..', '..', '..', '..', 'specs', 'governed-receipt-vectors.json');
const MONOREPO = existsSync(VEC_PATH);
const needsMonorepo = { skip: !MONOREPO && 'needs fixtures from the monorepo root; not present in a standalone checkout' };
const VEC = MONOREPO ? JSON.parse(readFileSync(VEC_PATH, 'utf-8')) : null;
const canonical = (o) => JSON.stringify(sortKeysDeep(o));

test('verify-cli legateReceiptPayload matches the golden vectors byte-for-byte', needsMonorepo, () => {
  for (const v of VEC.legate_receipt_payload) {
    assert.equal(legateReceiptPayload(v.input), v.expected, `drift in legate receipt payload (${v.name})`);
  }
});

test('verify-cli canonical JSON (sortKeysDeep) matches the golden vectors', needsMonorepo, () => {
  for (const v of VEC.canonical_json) {
    assert.equal(canonical(v.input), v.expected, `drift in canonical JSON (${v.name})`);
  }
});

test('verify-cli gate-tuple digest is sha256 over the locked canonical payload', needsMonorepo, () => {
  for (const v of VEC.gate_tuple_digest) {
    assert.equal(canonical(v.payload), v.expected_canonical, `drift in canonical for ${v.name}`);
    const digest = bytesToHex(sha256(utf8ToBytes(canonical(v.payload))));
    assert.equal(digest, bytesToHex(sha256(utf8ToBytes(v.expected_canonical))), 'digest derivation drifted');
  }
});
