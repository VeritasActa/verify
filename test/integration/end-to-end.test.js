/**
 * End-to-end integration tests.
 * Generates a receipt with a known keypair, verifies via the unified CLI engines.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalize } from '../../src/util/canonical.js';
import { detectFormat } from '../../src/detect.js';
import { verifyReceipt, verifyBundle } from '../../src/engines/ed25519-receipt.js';
import { verifyKnowledgeUnit } from '../../src/engines/knowledge-unit.js';

function generateEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubRaw = publicKey.export({ type: 'spki', format: 'der' });
  const pubHex = pubRaw.subarray(pubRaw.length - 32).toString('hex');
  return { publicKey, privateKey, pubHex };
}

function signPayload(privateKey, payload) {
  const canonical = canonicalize(payload);
  const sig = sign(null, Buffer.from(canonical, 'utf8'), privateKey);
  return sig.toString('hex');
}

test('integration: roundtrip passport-envelope receipt', async () => {
  const { privateKey, pubHex } = generateEd25519();
  const payload = {
    type: 'scopeblind:decision',
    spec: 'draft-farley-acta-signed-receipts-03',
    tool_name: 'web_search',
    decision: 'allow',
    issued_at: '2026-04-19T12:00:00.000Z',
    issuer_id: 'test-issuer',
    sequence: 1,
    previousReceiptHash: null,
  };
  const sigHex = signPayload(privateKey, payload);
  const receipt = {
    payload,
    signature: { alg: 'EdDSA', kid: 'test:key:1', sig: sigHex },
  };

  const detected = detectFormat(receipt);
  assert.equal(detected.mode, 'ed25519-passport');

  const r = await verifyReceipt(receipt, detected.mode, { publicKey: pubHex });
  assert.equal(r.valid, true);
  assert.equal(r.format, 'passport');
  assert.equal(r.kid, 'test:key:1');
  assert.equal(r.algorithm, 'EdDSA');
});

test('integration: tampered receipt is rejected', async () => {
  const { privateKey, pubHex } = generateEd25519();
  const payload = {
    type: 'x',
    spec: 'draft-farley-acta-signed-receipts-03',
    decision: 'allow',
    issued_at: '2026-04-19T00:00:00.000Z',
    sequence: 1,
    previousReceiptHash: null,
  };
  const sigHex = signPayload(privateKey, payload);
  const receipt = {
    payload: { ...payload, decision: 'deny' }, // tamper!
    signature: { alg: 'EdDSA', kid: 'k', sig: sigHex },
  };
  const r = await verifyReceipt(receipt, 'ed25519-passport', { publicKey: pubHex });
  assert.equal(r.valid, false);
});

test('integration: embedded key rejected by default', async () => {
  const receipt = {
    payload: {
      type: 'x',
      spec: 'draft-farley-acta-signed-receipts-03',
      public_key: 'a'.repeat(64),
    },
    signature: { alg: 'EdDSA', kid: 'k', sig: 'a'.repeat(128) },
  };
  const r = await verifyReceipt(receipt, 'ed25519-passport', {});
  assert.equal(r.valid, false);
  assert.equal(r.error, 'embedded_key_rejected');
});

test('integration: embedded key accepted with --allow-embedded-key (deprecated)', async () => {
  // Set up a real signed receipt
  const { privateKey, pubHex } = generateEd25519();
  const payload = {
    type: 'x',
    spec: 'draft-farley-acta-signed-receipts-03',
    decision: 'allow',
    issued_at: '2026-04-19T00:00:00.000Z',
    sequence: 1,
    previousReceiptHash: null,
    public_key: pubHex,
  };
  const sigHex = signPayload(privateKey, payload);
  const receipt = {
    payload,
    signature: { alg: 'EdDSA', kid: 'k', sig: sigHex },
  };
  const r = await verifyReceipt(receipt, 'ed25519-passport', { allowEmbeddedKey: true });
  assert.equal(r.valid, true);
  assert.equal(r.keySource, 'embedded-deprecated');
});

test('integration: hybrid PQ algorithm rejected cleanly', async () => {
  const receipt = {
    v: 2,
    type: 'x',
    algorithm: 'ed25519+ml-dsa-65',
    kid: 'k',
    issuer: 'i',
    issued_at: '2026-04-19T00:00:00.000Z',
    payload: {},
    signature: 'a'.repeat(128),
  };
  const r = await verifyReceipt(receipt, 'ed25519-receipt-v2', { publicKey: 'a'.repeat(64) });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'unsupported_algorithm');
});
