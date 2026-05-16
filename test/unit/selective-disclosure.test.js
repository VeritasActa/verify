/**
 * Unit tests for AIP-0002 selective disclosure verification.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  verifySelectiveDisclosure,
  listRedactedFields,
} from '../../src/engines/selective-disclosure.js';

function commit(salt, value) {
  return 'sha256:' + createHash('sha256').update(salt + JSON.stringify(value), 'utf8').digest('hex');
}

test('verifySelectiveDisclosure: valid disclosure', () => {
  const salt = 'a8f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5';
  const value = 'PAT-2026-08832';
  const receipt = {
    payload: { patient_id: 'sha256(salt + ...)' },
    _commitments: { 'payload.patient_id': commit(salt, value) },
    signature: 'x',
  };
  const r = verifySelectiveDisclosure(receipt, [
    { field: 'payload.patient_id', salt, value },
  ]);
  assert.equal(r.valid, true);
  assert.equal(r.disclosuresVerified, 1);
  assert.equal(r.checks[0].ok, true);
});

test('verifySelectiveDisclosure: invalid disclosure (wrong value)', () => {
  const salt = 'cafebabe';
  const receipt = {
    payload: { x: 'sha256(...)' },
    _commitments: { 'payload.x': commit(salt, 'real-value') },
    signature: 'x',
  };
  const r = verifySelectiveDisclosure(receipt, [
    { field: 'payload.x', salt, value: 'wrong-value' },
  ]);
  assert.equal(r.valid, false);
  assert.equal(r.error, 'commitment_mismatch');
  assert.equal(r.checks[0].ok, false);
});

test('verifySelectiveDisclosure: field not in _commitments', () => {
  const receipt = {
    payload: {},
    _commitments: { 'payload.a': 'sha256:x' },
  };
  const r = verifySelectiveDisclosure(receipt, [
    { field: 'payload.missing', salt: 'x', value: 'y' },
  ]);
  assert.equal(r.valid, false);
  assert.equal(r.checks[0].ok, false);
});

test('verifySelectiveDisclosure: empty disclosures returns valid=true', () => {
  const r = verifySelectiveDisclosure({ _commitments: {} }, []);
  assert.equal(r.valid, true);
  assert.equal(r.disclosuresVerified, 0);
});

test('listRedactedFields: returns keys of _commitments', () => {
  const receipt = {
    _commitments: {
      'payload.patient_id': 'sha256:a',
      'payload.diagnosis': 'sha256:b',
    },
  };
  const fields = listRedactedFields(receipt);
  assert.deepEqual(fields.sort(), ['payload.diagnosis', 'payload.patient_id']);
});

test('listRedactedFields: no _commitments returns empty', () => {
  assert.deepEqual(listRedactedFields({}), []);
});
