/**
 * Unit tests for conformance tier detection.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { detectTier } from '../../src/conformance.js';

test('detectTier: basic receipt is T1', () => {
  const t = detectTier({ mode: 'ed25519-passport', payloadFields: {} });
  assert.equal(t.tier, 1);
  assert.ok(t.features.includes('ed25519-signature'));
});

test('detectTier: receipt with chain linkage', () => {
  const t = detectTier({
    mode: 'ed25519-passport',
    payloadFields: { previousReceiptHash: 'sha256:abc' },
  });
  assert.equal(t.tier, 1);
  assert.ok(t.features.includes('chain-linkage'));
});

test('detectTier: selective disclosure bumps to T2', () => {
  const t = detectTier({
    mode: 'ed25519-passport',
    payloadFields: {},
    disclosuresVerified: 2,
  });
  assert.equal(t.tier, 2);
  assert.ok(t.features.includes('selective-disclosure'));
});

test('detectTier: hardware attestation bumps to T3', () => {
  const t = detectTier({
    mode: 'ed25519-passport',
    payloadFields: { attestation_mode: 'hardware:secure_element' },
  });
  assert.equal(t.tier, 3);
  assert.ok(t.features.some(f => f.startsWith('attestation:')));
});

test('detectTier: anchor_uri bumps to T3', () => {
  const t = detectTier({
    mode: 'ed25519-passport',
    payloadFields: { anchor_uri: 'oci://ghcr.io/x/y:z' },
  });
  assert.equal(t.tier, 3);
  assert.ok(t.features.includes('anchor-uri'));
});

test('detectTier: VOPRF mode bumps to T4', () => {
  const t = detectTier({
    mode: 'voprf-token',
    payloadFields: {},
    voprfVerified: true,
  });
  assert.equal(t.tier, 4);
  assert.ok(t.features.includes('voprf'));
});

test('detectTier: holder_binding alone bumps to T4', () => {
  const t = detectTier({
    mode: 'ed25519-passport',
    payloadFields: {
      holder_binding: { mode: 'jwk_thumbprint', thumbprint: 'x' },
    },
  });
  assert.equal(t.tier, 4);
  assert.ok(t.features.includes('holder-binding'));
});

test('detectTier: compliance_credit_ref surfaces but does not yet bump to T5', () => {
  const t = detectTier({
    mode: 'ed25519-passport',
    payloadFields: { compliance_credit_ref: 'https://x' },
  });
  assert.ok(t.features.includes('compliance-credit-ref'));
  assert.ok(t.tier < 5); // T5 requires v1.0+ full verification
});

test('detectTier: labels consistent with tier number', () => {
  const labels = ['T1 basic', 'T2 disclosure', 'T3 attestation', 'T4 privacy'];
  for (let tier = 1; tier <= 4; tier++) {
    const t = detectTier({
      mode: 'ed25519-passport',
      payloadFields: {
        // force each tier
        ...(tier >= 3 && { attestation_mode: 'hardware:secure_element' }),
        ...(tier >= 4 && { holder_binding: { mode: 'jwk_thumbprint', thumbprint: 'x' } }),
      },
      disclosuresVerified: tier >= 2 ? 1 : 0,
    });
    assert.equal(t.tier, tier);
    assert.equal(t.label, labels[tier - 1]);
  }
});
