/**
 * Unit tests for AIP-0005 T2 attestation-quote validator.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPairSync,
  sign as cryptoSign,
  createHash,
  createPrivateKey,
  createPublicKey,
} from 'node:crypto';

import { verifyAttestationQuote } from '../../src/engines/attestation-quote.js';

// ───── Structural ─────

test('verifyAttestationQuote: no payload → undecidable', () => {
  const r = verifyAttestationQuote({ receipt: null });
  assert.equal(r.valid, false);
  assert.equal(r.mode, 'undecidable');
});

test('verifyAttestationQuote: receipt without attestation_quote → undecidable', () => {
  const r = verifyAttestationQuote({
    receipt: { payload: {}, signature: { kid: 'k' } },
  });
  assert.equal(r.valid, false);
  assert.equal(r.error, 'no_attestation_quote');
});

test('verifyAttestationQuote: unknown format → undecidable', () => {
  const r = verifyAttestationQuote({
    receipt: {
      payload: {
        attestation_quote: { format: 'rubbish', quote: 'A', measured_kid: 'x' },
      },
      signature: { kid: 'x' },
    },
  });
  assert.equal(r.valid, false);
  assert.match(r.error, /unknown_format/);
});

test('verifyAttestationQuote: measured_kid ≠ signature.kid → invalid', () => {
  const r = verifyAttestationQuote({
    receipt: {
      payload: {
        attestation_quote: {
          format: 'atecc608b-signed-data-v1',
          quote: 'AA==',
          measured_kid: 'alice',
        },
      },
      signature: { kid: 'bob' },
    },
  });
  assert.equal(r.valid, false);
  assert.match(r.error, /measured_kid_does_not_match/);
});

// ───── TPM2 / SGX / SEV: structural-only in v0.5.4 ─────

test('verifyAttestationQuote: TPM2 quote (structural only in v0.5.4, non-strict)', () => {
  const r = verifyAttestationQuote({
    receipt: {
      payload: {
        attestation_mode: 'tpm2',
        attestation_quote: {
          format: 'tpm2-quote-v1',
          quote: 'AAAA',
          measured_kid: 'x',
        },
      },
      signature: { kid: 'x' },
    },
  });
  assert.equal(r.valid, true);
  assert.equal(r.mode, 'undecidable');
  assert.equal(r.kid_match, true);
});

test('verifyAttestationQuote: TPM2 quote with --strict fails', () => {
  const r = verifyAttestationQuote({
    receipt: {
      payload: {
        attestation_quote: {
          format: 'tpm2-quote-v1', quote: 'AAAA', measured_kid: 'x',
        },
      },
      signature: { kid: 'x' },
    },
    strict: true,
  });
  assert.equal(r.valid, false);
  assert.match(r.error, /platform_validator_not_yet_shipped/);
});

// ───── ATECC608B ─────

test('verifyAttestationQuote: ATECC608B quote with no trust anchor is undecidable', () => {
  const r = verifyAttestationQuote({
    receipt: {
      payload: {
        attestation_quote: {
          format: 'atecc608b-signed-data-v1',
          quote: 'AAAA',
          measured_kid: 'x',
        },
      },
      signature: { kid: 'x' },
    },
    trustAnchors: {},
  });
  assert.equal(r.valid, true);  // permissive when no trust anchor + not strict
  assert.equal(r.mode, 'undecidable');
});

test('verifyAttestationQuote: ATECC608B with valid ECDSA signature verifies', () => {
  // Generate a fresh ECDSA P-256 keypair to act as the provisioning CA.
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const caPem = publicKey.export({ type: 'spki', format: 'pem' });

  // Build a receipt payload.
  const payload = {
    type: 'decision-receipt',
    action: 'Bash',
    issued_at: '2026-04-20T00:00:00Z',
    issuer_id: 'test',
  };
  // Canonicalize it the same way the engine does.
  function jcs(v) {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
    const keys = Object.keys(v).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
  }
  const payloadBytes = Buffer.from(jcs(payload), 'utf-8');

  // Sign with the CA key to simulate ATECC608B.
  const sig = cryptoSign('sha256', payloadBytes, privateKey);

  const receipt = {
    payload: {
      ...payload,
      attestation_mode: 'atecc608b',
      attestation_quote: {
        format: 'atecc608b-signed-data-v1',
        quote: sig.toString('base64'),
        measured_kid: 'x',
      },
    },
    signature: { kid: 'x' },
  };

  const r = verifyAttestationQuote({
    receipt,
    trustAnchors: { atecc608b: caPem },
  });
  assert.equal(r.valid, true);
  assert.equal(r.mode, 'cryptographic');
  assert.equal(r.platform, 'atecc608b');
});

test('verifyAttestationQuote: ATECC608B with wrong CA key fails', () => {
  const kp1 = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const kp2 = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const wrongCaPem = kp2.publicKey.export({ type: 'spki', format: 'pem' });

  const payload = { type: 'decision-receipt', action: 'Bash', issued_at: '2026-04-20T00:00:00Z' };
  function jcs(v) {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(jcs).join(',') + ']';
    const keys = Object.keys(v).sort();
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(v[k])).join(',') + '}';
  }
  const payloadBytes = Buffer.from(jcs(payload), 'utf-8');
  const sig = cryptoSign('sha256', payloadBytes, kp1.privateKey);

  const receipt = {
    payload: {
      ...payload,
      attestation_quote: {
        format: 'atecc608b-signed-data-v1',
        quote: sig.toString('base64'),
        measured_kid: 'x',
      },
    },
    signature: { kid: 'x' },
  };

  const r = verifyAttestationQuote({
    receipt,
    trustAnchors: { atecc608b: wrongCaPem },
  });
  assert.equal(r.valid, false);
  assert.match(r.error, /atecc608b_signature_invalid/);
});

// ───── Apple Secure Enclave (structural correctness) ─────

test('verifyAttestationQuote: Apple SE with no CA → undecidable', () => {
  const r = verifyAttestationQuote({
    receipt: {
      payload: {
        attestation_quote: {
          format: 'apple-secure-enclave-v1',
          quote: Buffer.alloc(200).toString('base64'),
          measured_kid: 'x',
        },
      },
      signature: { kid: 'x' },
    },
    trustAnchors: {},
  });
  assert.equal(r.valid, true);
  assert.equal(r.mode, 'undecidable');
});

test('verifyAttestationQuote: Apple SE quote too short fails cryptographic check', () => {
  const kp = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const caPem = kp.publicKey.export({ type: 'spki', format: 'pem' });
  const r = verifyAttestationQuote({
    receipt: {
      payload: {
        attestation_quote: {
          format: 'apple-secure-enclave-v1',
          quote: Buffer.alloc(100).toString('base64'),  // too short
          measured_kid: 'x',
        },
      },
      signature: { kid: 'x' },
    },
    trustAnchors: { 'apple-secure-enclave': caPem },
  });
  assert.equal(r.valid, false);
  assert.match(r.error, /quote_too_short/);
});
