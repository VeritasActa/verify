/**
 * Unit tests for DSSE envelope engine (Sigstore compat).
 *
 * Covers pre-authentication encoding, wrap/unwrap symmetry, signature
 * verification against Ed25519 trust anchors, and rejection of bad
 * payload types.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

import {
  dssePAE,
  wrapDSSE,
  unwrapDSSE,
  verifyDSSE,
  dsseDigest,
  ACTA_RECEIPT_PAYLOAD_TYPE,
  ACTA_KU_PAYLOAD_TYPE,
  INTOTO_STATEMENT_TYPE,
} from '../../src/engines/dsse.js';

// Generate a fresh Ed25519 keypair and return its raw 32-byte public key in hex.
function mkKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const rawPub = spki.subarray(spki.length - 32);
  return {
    publicKey,
    privateKey,
    pubHex: rawPub.toString('hex'),
  };
}

test('dssePAE: encoding matches the spec format', () => {
  const pae = dssePAE('application/x-test', Buffer.from('abc'));
  // Expected: "DSSEv1 18 application/x-test 3 abc"
  assert.equal(pae.toString('utf-8'), 'DSSEv1 18 application/x-test 3 abc');
});

test('wrapDSSE / unwrapDSSE: round-trips payload JSON', () => {
  const receipt = {
    payload: { type: 'decision-receipt', action: 'x' },
    signature: { alg: 'ed25519', kid: 'k', sig: '00' },
  };
  const env = wrapDSSE(receipt, ACTA_RECEIPT_PAYLOAD_TYPE, [
    { keyid: 'sha256:abc', sigB64: 'AA==' },
  ]);
  const unw = unwrapDSSE(env);
  assert.equal(unw.ok, true);
  assert.equal(unw.payload_type, ACTA_RECEIPT_PAYLOAD_TYPE);
  assert.deepEqual(unw.payload, receipt);
});

test('unwrapDSSE: rejects missing fields', () => {
  assert.equal(unwrapDSSE({}).ok, false);
  assert.equal(unwrapDSSE({ payloadType: 'x' }).ok, false);
  assert.equal(unwrapDSSE(null).ok, false);
});

test('verifyDSSE: valid Ed25519 signature over PAE → valid', () => {
  const { privateKey, pubHex } = mkKeyPair();
  const receipt = { payload: { type: 'decision-receipt' } };
  const body = Buffer.from(JSON.stringify(receipt), 'utf-8');
  const pae = dssePAE(ACTA_RECEIPT_PAYLOAD_TYPE, body);
  const sig = cryptoSign(null, pae, privateKey);

  const envelope = {
    payloadType: ACTA_RECEIPT_PAYLOAD_TYPE,
    payload: body.toString('base64'),
    signatures: [{ keyid: 'test-kid', sig: sig.toString('base64') }],
  };

  const r = verifyDSSE({
    envelope,
    trustAnchors: { 'test-kid': pubHex },
  });
  assert.equal(r.valid, true);
  assert.equal(r.signatures[0].sig_valid, true);
});

test('verifyDSSE: tampered payload → invalid', () => {
  const { privateKey, pubHex } = mkKeyPair();
  const receipt = { payload: { type: 'decision-receipt' } };
  const pae = dssePAE(ACTA_RECEIPT_PAYLOAD_TYPE,
    Buffer.from(JSON.stringify(receipt), 'utf-8'));
  const sig = cryptoSign(null, pae, privateKey);

  const tampered = { payload: { type: 'decision-receipt', action: 'tampered' } };
  const envelope = {
    payloadType: ACTA_RECEIPT_PAYLOAD_TYPE,
    payload: Buffer.from(JSON.stringify(tampered), 'utf-8').toString('base64'),
    signatures: [{ keyid: 't', sig: sig.toString('base64') }],
  };

  const r = verifyDSSE({ envelope, trustAnchors: { t: pubHex } });
  assert.equal(r.valid, false);
});

test('verifyDSSE: signature with no trust anchor → invalid with reason', () => {
  const { privateKey } = mkKeyPair();
  const body = Buffer.from('{"x":1}');
  const sig = cryptoSign(null, dssePAE(ACTA_RECEIPT_PAYLOAD_TYPE, body), privateKey);

  const envelope = {
    payloadType: ACTA_RECEIPT_PAYLOAD_TYPE,
    payload: body.toString('base64'),
    signatures: [{ keyid: 'unknown-kid', sig: sig.toString('base64') }],
  };
  const r = verifyDSSE({ envelope, trustAnchors: {} });
  assert.equal(r.valid, false);
  assert.equal(r.signatures[0].reason, 'no_trust_anchor');
});

test('verifyDSSE: accepts in-toto statement type by default', () => {
  const { privateKey, pubHex } = mkKeyPair();
  const statement = {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: 'x', digest: { sha256: 'ab'.repeat(32) } }],
    predicateType: 'scopeblind.decision',
  };
  const body = Buffer.from(JSON.stringify(statement), 'utf-8');
  const sig = cryptoSign(null, dssePAE(INTOTO_STATEMENT_TYPE, body), privateKey);

  const envelope = {
    payloadType: INTOTO_STATEMENT_TYPE,
    payload: body.toString('base64'),
    signatures: [{ keyid: 'it', sig: sig.toString('base64') }],
  };
  const r = verifyDSSE({ envelope, trustAnchors: { it: pubHex } });
  assert.equal(r.valid, true);
});

test('verifyDSSE: rejects unsupported payload type', () => {
  const { privateKey, pubHex } = mkKeyPair();
  const body = Buffer.from('{}');
  const sig = cryptoSign(null, dssePAE('application/x-random', body), privateKey);
  const envelope = {
    payloadType: 'application/x-random',
    payload: body.toString('base64'),
    signatures: [{ keyid: 'k', sig: sig.toString('base64') }],
  };
  const r = verifyDSSE({ envelope, trustAnchors: { k: pubHex } });
  assert.equal(r.valid, false);
  assert.match(r.error, /dsse_unsupported_payload_type/);
});

test('verifyDSSE: KU payload type accepted', () => {
  const { privateKey, pubHex } = mkKeyPair();
  const body = Buffer.from('{"bundle":{"type":"ku"}}');
  const sig = cryptoSign(null, dssePAE(ACTA_KU_PAYLOAD_TYPE, body), privateKey);
  const envelope = {
    payloadType: ACTA_KU_PAYLOAD_TYPE,
    payload: body.toString('base64'),
    signatures: [{ keyid: 'k', sig: sig.toString('base64') }],
  };
  const r = verifyDSSE({ envelope, trustAnchors: { k: pubHex } });
  assert.equal(r.valid, true);
});

test('dsseDigest: deterministic for identical envelopes', () => {
  const env = {
    payloadType: ACTA_RECEIPT_PAYLOAD_TYPE,
    payload: Buffer.from('body').toString('base64'),
    signatures: [{ keyid: 'k', sig: 'AA==' }],
  };
  const a = dsseDigest(env);
  const b = dsseDigest(env);
  assert.equal(a, b);
  assert.equal(a.length, 64); // hex
});
