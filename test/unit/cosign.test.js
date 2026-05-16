/**
 * Unit tests for cosignature engine (bilateral / N-ary).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

import { verifyCosignatures, attachCosignature } from '../../src/engines/cosign.js';
import { canonicalize } from '../../src/util/canonical.js';

function mkKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const rawPub = spki.subarray(spki.length - 32);
  return { privateKey, pubHex: rawPub.toString('hex') };
}

function signPayload(payload, privateKey) {
  const bytes = canonicalize(payload);
  return cryptoSign(null, bytes, privateKey).toString('hex');
}

test('verifyCosignatures: envelope without cosignatures → vacuously valid', () => {
  const env = { payload: { type: 'decision-receipt' }, signature: { alg: 'EdDSA', kid: 'x', sig: '00' } };
  const r = verifyCosignatures({ envelope: env, trustAnchors: {} });
  assert.equal(r.valid, true);
  assert.equal(r.total, 0);
});

test('attachCosignature: adds to empty envelope', () => {
  const env = { payload: {}, signature: {} };
  attachCosignature(env, { alg: 'EdDSA', kid: 'server', sig: 'deadbeef' });
  assert.equal(env.cosignatures.length, 1);
  assert.equal(env.cosignatures[0].kid, 'server');
});

test('attachCosignature: appends to existing array', () => {
  const env = { payload: {}, signature: {}, cosignatures: [{ alg: 'EdDSA', kid: 'a', sig: 'aa' }] };
  attachCosignature(env, { kid: 'b', sig: 'bb' });
  assert.equal(env.cosignatures.length, 2);
});

test('attachCosignature: rejects missing kid/sig', () => {
  assert.throws(() => attachCosignature({}, { sig: 'x' }));
  assert.throws(() => attachCosignature({}, { kid: 'x' }));
});

test('verifyCosignatures: valid bilateral (agent + server) verifies', () => {
  const agent = mkKey();
  const server = mkKey();
  const payload = { type: 'decision-receipt', action: 'Bash', issued_at: '2026-04-20T00:00:00Z' };

  const env = {
    payload,
    signature: { alg: 'EdDSA', kid: 'agent', sig: signPayload(payload, agent.privateKey) },
    cosignatures: [
      { alg: 'EdDSA', kid: 'server', sig: signPayload(payload, server.privateKey) },
    ],
  };

  const r = verifyCosignatures({
    envelope: env,
    trustAnchors: { 'server': server.pubHex },
  });
  assert.equal(r.valid, true);
  assert.equal(r.total, 1);
  assert.equal(r.valid_count, 1);
  assert.equal(r.signatures[0].sig_valid, true);
});

test('verifyCosignatures: tampered payload → cosignature fails', () => {
  const server = mkKey();
  const payload = { type: 'decision-receipt', action: 'Bash' };
  const env = {
    payload: { ...payload, action: 'tampered' },   // payload modified AFTER signing
    signature: { alg: 'EdDSA', kid: 'agent', sig: '00' },
    cosignatures: [
      { alg: 'EdDSA', kid: 'server', sig: signPayload(payload, server.privateKey) },
    ],
  };
  const r = verifyCosignatures({
    envelope: env,
    trustAnchors: { 'server': server.pubHex },
  });
  assert.equal(r.valid, false);
  assert.equal(r.signatures[0].reason, 'signature_invalid');
});

test('verifyCosignatures: cosig kid not in trust anchors → fails by default', () => {
  const server = mkKey();
  const payload = { x: 1 };
  const env = {
    payload,
    signature: {},
    cosignatures: [
      { alg: 'EdDSA', kid: 'stranger', sig: signPayload(payload, server.privateKey) },
    ],
  };
  const r = verifyCosignatures({
    envelope: env,
    trustAnchors: { /* stranger not here */ },
  });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'cosignature_no_trust_anchor');
});

test('verifyCosignatures: N-ary with mixed validity (one bad, require all)', () => {
  const a = mkKey();
  const b = mkKey();
  const payload = { x: 1 };
  const env = {
    payload,
    signature: {},
    cosignatures: [
      { alg: 'EdDSA', kid: 'a', sig: signPayload(payload, a.privateKey) },
      { alg: 'EdDSA', kid: 'b', sig: signPayload({ x: 2 }, b.privateKey) }, // signs WRONG payload
    ],
  };
  const r = verifyCosignatures({
    envelope: env,
    trustAnchors: { 'a': a.pubHex, 'b': b.pubHex },
  });
  assert.equal(r.valid, false);
  assert.equal(r.valid_count, 1);
  assert.equal(r.signatures[0].sig_valid, true);
  assert.equal(r.signatures[1].sig_valid, false);
});

test('verifyCosignatures: N-ary with mixed validity, require all valid=false → passes', () => {
  const a = mkKey();
  const b = mkKey();
  const payload = { x: 1 };
  const env = {
    payload,
    signature: {},
    cosignatures: [
      { alg: 'EdDSA', kid: 'a', sig: signPayload(payload, a.privateKey) },
      { alg: 'EdDSA', kid: 'b', sig: signPayload({ x: 2 }, b.privateKey) },
    ],
  };
  const r = verifyCosignatures({
    envelope: env,
    trustAnchors: { 'a': a.pubHex, 'b': b.pubHex },
    requireAllValid: false,
  });
  assert.equal(r.valid, true);
  assert.equal(r.valid_count, 1);
});

test('verifyCosignatures: malformed entry (missing sig) → invalid', () => {
  const env = {
    payload: {},
    signature: {},
    cosignatures: [{ alg: 'EdDSA', kid: 'x' }],  // no sig
  };
  const r = verifyCosignatures({ envelope: env, trustAnchors: { x: '00'.repeat(32) } });
  assert.equal(r.valid, false);
  assert.equal(r.signatures[0].reason, 'malformed_cosignature_entry');
});

test('verifyCosignatures: base64-encoded sig accepted (not just hex)', () => {
  const server = mkKey();
  const payload = { x: 1 };
  const sigHex = signPayload(payload, server.privateKey);
  const sigB64 = Buffer.from(sigHex, 'hex').toString('base64');
  const env = {
    payload,
    signature: {},
    cosignatures: [{ alg: 'EdDSA', kid: 'server', sig: sigB64 }],
  };
  const r = verifyCosignatures({
    envelope: env,
    trustAnchors: { 'server': server.pubHex },
  });
  assert.equal(r.valid, true);
});
