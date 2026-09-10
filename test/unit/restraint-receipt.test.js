/**
 * Restraint-receipt binding verification.
 *
 * A restraint receipt is a Legate governed receipt (tool gate.restrain) that
 * additionally carries openable detail: the disclosed denial outcome binds into
 * result_sha256 and the (optionally withheld) proposed order binds into
 * input_sha256. The verifier re-hashes both and proves the disclosed detail is
 * exactly what was signed, so the receipt proves WHAT was prevented and WHY.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519';
import { utf8ToBytes, bytesToHex } from '@noble/hashes/utils';
import { canonicalize, sha256Hex } from '../../src/util/canonical.js';
import { verifyLegateGovernedReceipt, verifyRestraintBindings } from '../../src/engines/legate-governed-receipt.js';

const PRIV = new Uint8Array(32).fill(7);
const VK = bytesToHex(ed25519.getPublicKey(PRIV));

// Mint a restraint receipt the same way scopeblind-pm/src/restraint.ts does.
function mintRestraint({ proposed, salt = 'restraint-test-salt', outcome }) {
  const input_sha256 = sha256Hex(`${salt}|${canonicalize(proposed)}`);
  const result_sha256 = sha256Hex(canonicalize(outcome));
  const at = '2026-06-21T12:00:00.000Z';
  const id = `restraint-${sha256Hex(`${input_sha256}|${result_sha256}`).slice(0, 16)}`;
  const tool = 'gate.restrain';
  const decision = 'DENY';
  const payload = ['scopeblind.receipt.v1', id, tool, decision, input_sha256, result_sha256, at].join('|');
  const signature = bytesToHex(ed25519.sign(utf8ToBytes(payload), PRIV));
  return {
    type: 'scopeblind.agent_vault.receipt.v1',
    id, at, tool, decision, input_sha256, result_sha256,
    signature, verification_key: VK,
    restraint: { salt, proposed, outcome },
  };
}

const OUTCOME = {
  determining: ['manifest:forbidden-instrument', 'concentration-single-name'],
  risk_band: 'authority',
  mandate_digest: 'abcd1234',
  layers: { manifest: 'deny' },
};
const PROPOSED = { symbol: 'TSLA', side: 'buy', qty: 5000, notional: 2000000 };

test('a restraint receipt verifies and both disclosed bindings hold', () => {
  const r = mintRestraint({ proposed: PROPOSED, outcome: OUTCOME });
  const res = verifyLegateGovernedReceipt(r);
  assert.equal(res.valid, true, 'signature is valid');
  assert.equal(res.kind, 'restraint');
  assert.ok(res.restraint, 'restraint bindings are attached');
  assert.equal(res.restraint.outcome_bound, true, 'outcome re-hashes to result_sha256');
  assert.equal(res.restraint.proposed_bound, true, 'proposed re-hashes (under salt) to input_sha256');
  assert.deepEqual(res.restraint.determining, OUTCOME.determining);
  assert.equal(res.restraint.risk_band, 'authority');
  assert.ok(res.proves.some((p) => /Restraint: the gate blocked/.test(p)), 'restraint proof line is present');
});

test('position-blind: the proposed order can be withheld and the outcome still binds', () => {
  const r = mintRestraint({ proposed: PROPOSED, outcome: OUTCOME });
  r.restraint.proposed = null; // withhold the order after signing (input hash is unchanged)
  const res = verifyLegateGovernedReceipt(r);
  assert.equal(res.valid, true, 'signature still valid');
  assert.equal(res.restraint.outcome_bound, true);
  assert.equal(res.restraint.proposed_bound, null, 'withheld order is reported as position-blind');
  assert.ok(res.proves.some((p) => /Position-blind/.test(p)));
});

test('tampering the disclosed outcome breaks the binding but not the signature', () => {
  const r = mintRestraint({ proposed: PROPOSED, outcome: OUTCOME });
  r.restraint.outcome.risk_band = 'standard'; // lie about the severity
  const res = verifyLegateGovernedReceipt(r);
  assert.equal(res.valid, true, 'the signature is over the original hashes and is still valid');
  assert.equal(res.restraint.outcome_bound, false, 'the altered outcome no longer re-hashes to result_sha256');
  assert.ok(res.limitations.some((l) => /did NOT re-hash to the signed result hash/.test(l)));
});

test('tampering the disclosed order breaks only the proposed binding', () => {
  const r = mintRestraint({ proposed: PROPOSED, outcome: OUTCOME });
  r.restraint.proposed.notional = 1; // understate the blocked size
  const res = verifyLegateGovernedReceipt(r);
  assert.equal(res.valid, true);
  assert.equal(res.restraint.outcome_bound, true, 'outcome still binds');
  assert.equal(res.restraint.proposed_bound, false, 'the altered order no longer re-hashes to input_sha256');
});

test('forging a signed hash invalidates the signature outright', () => {
  const r = mintRestraint({ proposed: PROPOSED, outcome: OUTCOME });
  r.result_sha256 = '0'.repeat(64);
  const res = verifyLegateGovernedReceipt(r);
  assert.equal(res.valid, false);
  assert.equal(res.error, 'invalid_signature');
});

test('verifyRestraintBindings is a no-op-safe pure check', () => {
  const r = mintRestraint({ proposed: PROPOSED, outcome: OUTCOME });
  const b = verifyRestraintBindings(r);
  assert.equal(b.outcome_bound, true);
  assert.equal(b.proposed_bound, true);
  // A receipt with no restraint detail returns unbound, not a throw.
  const empty = verifyRestraintBindings({ result_sha256: 'x', input_sha256: 'y' });
  assert.equal(empty.outcome_bound, false);
  assert.equal(empty.proposed_bound, null);
});
