import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { utf8ToBytes, bytesToHex } from '@noble/hashes/utils';
import { detectFormat } from '../../src/detect.js';
import {
  verifyLegateGovernedReceipt,
  legateReceiptPayload,
  GOVERNED_RECEIPT_KINDS,
} from '../../src/engines/legate-governed-receipt.js';
import { exitCodeFor } from '../../src/errors.js';

function mkSigner() {
  const priv = new Uint8Array(randomBytes(32));
  return { priv, vk: bytesToHex(ed25519.getPublicKey(priv)) };
}

/**
 * Build and sign a Legate governed receipt EXACTLY as
 * scopeblind-pm/src/governed-actions.ts and the desktop daemon do:
 * Ed25519 over the UTF-8 bytes of the flat canonical payload (not a digest).
 */
function signGoverned(fields, signer = mkSigner()) {
  const r = {
    type: 'scopeblind.agent_vault.receipt.v1',
    id: 'rcpt-001',
    at: '2026-06-15T09:31:00.000Z',
    tool: 'gate.approve',
    decision: 'APPROVAL_REQUIRED',
    input_sha256: 'a'.repeat(64),
    result_sha256: 'b'.repeat(64),
    ...fields,
  };
  r.verification_key = signer.vk;
  r.signature = bytesToHex(ed25519.sign(utf8ToBytes(legateReceiptPayload(r)), signer.priv));
  return r;
}

test('detect classifies the flat governed envelope as legate-governed-receipt', () => {
  const r = signGoverned({});
  const d = detectFormat(r);
  assert.equal(d.mode, 'legate-governed-receipt');
  assert.ok(d.signals.includes('tool+input_sha256+result_sha256+signature+verification_key'));
});

test('a genuine daemon-signed receipt verifies via the open engine', () => {
  const r = signGoverned({ tool: 'gate.approve', decision: 'approved' });
  const out = verifyLegateGovernedReceipt(r);
  assert.equal(out.valid, true);
  assert.equal(out.format, 'legate-governed-receipt');
  assert.equal(out.kind, 'approval');
  assert.equal(out.kindRecognized, true);
  assert.equal(out.publicKey, r.verification_key);
  assert.equal(out.signedPayload, legateReceiptPayload(r));
});

test('a single tampered byte in the action fails the signature', () => {
  const r = signGoverned({ tool: 'gate.approve', decision: 'approved' });
  // Flip the decision after signing — the bytes no longer match the signature.
  const tampered = { ...r, decision: 'declined' };
  const out = verifyLegateGovernedReceipt(tampered);
  assert.equal(out.valid, false);
  assert.equal(out.error, 'invalid_signature');
});

test('tampering with the input hash (the action preimage binding) fails', () => {
  const r = signGoverned({ tool: 'instruction', decision: 'route' });
  const tampered = { ...r, input_sha256: 'f'.repeat(64) };
  assert.equal(verifyLegateGovernedReceipt(tampered).valid, false);
});

test('--key pinning rejects a receipt signed by an unexpected key', () => {
  const r = signGoverned({});
  const out = verifyLegateGovernedReceipt(r, { publicKey: 'd'.repeat(64) });
  assert.equal(out.valid, false);
  assert.equal(out.error, 'key_mismatch');
  assert.equal(out.expectedKey, 'd'.repeat(64));
});

test('--key pinning accepts a receipt signed by the expected key', () => {
  const signer = mkSigner();
  const r = signGoverned({}, signer);
  assert.equal(verifyLegateGovernedReceipt(r, { publicKey: signer.vk }).valid, true);
});

test('every governed-action kind is recognized and round-trips', () => {
  for (const [tool, kind] of Object.entries(GOVERNED_RECEIPT_KINDS)) {
    const r = signGoverned({ tool, id: `rcpt-${tool}` });
    const out = verifyLegateGovernedReceipt(r);
    assert.equal(out.valid, true, `${tool} should verify`);
    assert.equal(out.kind, kind, `${tool} -> ${kind}`);
    assert.equal(out.kindRecognized, true);
  }
});

test('an unrecognized tool still verifies cryptographically but is flagged unrecognized', () => {
  const r = signGoverned({ tool: 'made.up.tool' });
  const out = verifyLegateGovernedReceipt(r);
  assert.equal(out.valid, true);
  assert.equal(out.kindRecognized, false);
});

test('malformed receipts are rejected with structured errors', () => {
  assert.equal(verifyLegateGovernedReceipt(null).error, 'unknown_format');
  const noSig = signGoverned({});
  delete noSig.signature;
  assert.equal(verifyLegateGovernedReceipt(noSig).error, 'missing_signature');
  const badHex = signGoverned({});
  badHex.signature = 'zz';
  assert.equal(verifyLegateGovernedReceipt(badHex).error, 'malformed_hex');
});

test('no false collision: a governed receipt is not a gate tuple, and vice versa', () => {
  const governed = signGoverned({});
  assert.equal(detectFormat(governed).mode, 'legate-governed-receipt');
  // A gate tuple carries a payload object + digest and must NOT be misrouted here.
  const tuple = { payload: { schema: 'scopeblind.gate.decision/2' }, digest: 'a'.repeat(64), signature: 'ab', verification_key: 'cd' };
  assert.equal(detectFormat(tuple).mode, 'gate-receipt-tuple');
});

test('error codes map to a nonzero exit', () => {
  const out = verifyLegateGovernedReceipt(signGoverned({ decision: 'x' }) && { ...signGoverned({}), signature: 'a'.repeat(128) });
  assert.notEqual(out.valid, true);
  assert.ok(exitCodeFor(out.error) > 0, `${out.error} should be a nonzero exit`);
});
